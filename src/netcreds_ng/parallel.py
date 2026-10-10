"""Parallel analysis: one stream of frames split across worker processes, merged back into one order.

Every worker reads every frame of every file, in order, but analyses only the frames it owns: a
frame belongs to the worker picked by a hash of its two IP addresses, so every connection, every IP
fragment and every flow between the same two hosts stays in one worker. For the frames it does not
own a worker only advances its clock (``Engine.skip_frame``), so idle flows are swept at the same
frames as in a single engine.

Workers run decoding and the protocol plugins. They tag what they publish with
``Engine.emit_order`` and send it to the parent in batches; the parent merges the batches back into
the order a single engine would have produced and runs de-duplication, enrichers and sinks there.
The output is the output of ``-j 1``, with these exceptions (docs/guide/analysing-captures.md):

* limits apply per worker: the flow-table cap (``MAX_FLOWS``) and the IP defragmenter's caps
  (``ipfrag.MAX_PENDING``, ``RECENT_KEEP``);
* fragment expiry is driven by the fragments a worker sees, so when capture timestamps go
  backwards, a datagram that one engine would expire (because of a later-stamped fragment of
  another host pair) can still be reassembled;
* flow ids (``FlowInfo.flow_id``) are numbered per worker; findings do not carry them;
* a third-party plugin that correlates traffic between *different* host pairs only sees its
  own worker's share.
"""

from __future__ import annotations

import itertools
import logging
import multiprocessing
import os
import queue
import traceback
import zlib
from collections import deque
from typing import TYPE_CHECKING, Any

from netcreds_ng.engine.decode import DLT_EN10MB, l3_offset
from netcreds_ng.engine.engine import Engine, relaxed_gc
from netcreds_ng.engine.pcapio import CaptureFormatError, RawFrame
from netcreds_ng.engine.pipeline import Deduplicator, Pipeline
from netcreds_ng.engine.sources import file_frames
from netcreds_ng.model import Finding, RunStats

if TYPE_CHECKING:
    from netcreds_ng.session import Session, SessionConfig

log = logging.getLogger(__name__)

#: Below this much capture data, starting worker processes costs more than it saves.
PARALLEL_MIN_BYTES = 16 * 1024 * 1024
#: Frames between two batches a worker sends to the parent.
BATCH_FRAMES = 4096
#: Sorts after every frame position: findings from the end of the run (Engine.finish).
_END = 1 << 62

# Event kinds, in the order of their tag (position, phase, flow position, sequence).
_SOURCE, _FINDING, _ERROR = 0, 1, 2
Event = tuple[int, int, int, int, int, Any]


def default_workers() -> int:
    """Workers for ``-j 0``: one per physical core (analysis is CPU-bound; hyper-threads add little)."""
    try:
        import psutil

        cores = psutil.cpu_count(logical=False)
    except Exception:  # noqa: BLE001 - psutil cannot tell on some platforms
        cores = None
    return max(1, cores or os.cpu_count() or 1)


def route(frame: RawFrame, workers: int) -> int:
    """The worker that analyses ``frame``: by its unordered pair of IP addresses.

    Frames without a readable IP header all go to worker 0, which counts them as a single engine would.
    """
    data = frame.data
    if frame.linktype == DLT_EN10MB and data[12:14] == b"\x08\x00" and len(data) >= 34 and data[14] >> 4 == 4:
        a, b = data[26:30], data[30:34]  # untagged Ethernet + IPv4, the common case, without l3_offset
        return zlib.crc32(a + b if a <= b else b + a) % workers
    res = l3_offset(frame)
    if res is None:
        return 0
    off, data = res[0], frame.data
    if len(data) <= off:
        return 0
    version = data[off] >> 4  # decode_ip goes by the version nibble, not by the link-layer type
    if version == 4 and len(data) >= off + 20:
        a, b = data[off + 12 : off + 16], data[off + 16 : off + 20]
    elif version == 6 and len(data) >= off + 40:
        a, b = data[off + 8 : off + 24], data[off + 24 : off + 40]
    else:
        return 0
    return zlib.crc32(a + b if a <= b else b + a) % workers


class _TaggedErrors(list[str]):
    """The worker pipeline's error list: also records each error as a tagged event."""

    def __init__(self, engine: Engine, events: list[Event], seq: itertools.count[int]) -> None:
        super().__init__()
        self._engine, self._events, self._seq = engine, events, seq

    def append(self, msg: str) -> None:
        super().append(msg)
        self._events.append((*self._engine.emit_order, next(self._seq), _ERROR, msg))


def _worker(wid: int, workers: int, paths: list[str], config: SessionConfig, plugins: list[str],
            merge_secrets: bool, log_level: int, out: Any) -> None:  # fmt: skip
    try:
        out.put(("done", wid, *_analyse_share(wid, workers, paths, config, plugins, merge_secrets, log_level, out)))
    except BaseException:  # noqa: BLE001 - reported to the parent, which raises it
        out.put(("crash", wid, traceback.format_exc()))


def _analyse_share(wid: int, workers: int, paths: list[str], config: SessionConfig, plugins: list[str],
                   merge_secrets: bool, log_level: int, out: Any) -> tuple[list[Event], RunStats]:  # fmt: skip
    from netcreds_ng.plugins.registry import load_registry

    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")
    registry = load_registry(plugin_dirs=config.plugin_dirs)
    stats = RunStats()
    events: list[Event] = []
    seq = itertools.count()
    tls = None
    if config.tls_keylog:
        from netcreds_ng.engine.tls import KeyLog, TLSDecryptor

        tls = TLSDecryptor(KeyLog(config.tls_keylog))
    pipeline = Pipeline(stats, dedup=Deduplicator("off"))  # de-duplication runs in the parent
    # The parent's plugins, by name: the parent may have been given a registry built differently.
    protocols = registry.select_protocols(options=config.plugin_options, only=plugins) if plugins else []
    engine = Engine(protocols, pipeline, stats, exclude_hosts=config.exclude_hosts, tls=tls)
    engine._merge_secrets = merge_secrets  # cross-plugin merging (E-10) follows the parent's --dedup
    pipeline.listeners.append(lambda f: events.append((*engine.emit_order, next(seq), _FINDING, f)))
    pipeline.errors = _TaggedErrors(engine, events, seq)

    def flush() -> None:
        out.put(("batch", wid, engine.position, events.copy()))
        events.clear()

    with relaxed_gc():
        for path in paths:
            if wid == 0:  # sinks hear about each file before its findings (Session.run_file)
                events.append((engine.position + 1, -1, 0, next(seq), _SOURCE, path))
            try:
                for frame in file_frames(path):
                    if route(frame, workers) == wid:
                        engine.process_frame(frame)
                    else:
                        engine.skip_frame(frame.timestamp)
                    if engine.position % BATCH_FRAMES == 0:
                        flush()
            except CaptureFormatError as exc:
                stats.source_errors.append(f"{path}: {exc}")
            except OSError as exc:
                stats.source_errors.append(f"{path}: {exc.strerror or exc}")
        engine.position = _END
        engine.finish()
    if wid != 0:
        stats.source_errors.clear()  # every worker read the same files: worker 0 reports their errors
    return events, stats


def run_parallel(session: Session, paths: list[str], workers: int) -> None:
    """Analyse ``paths`` (in order, as one stream) with ``workers`` processes, publishing into ``session``."""
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    plugins = [p.name for p in session.engine.plugins]
    args = (workers, paths, session.config, plugins, session.engine._merge_secrets,
            logging.getLogger().getEffectiveLevel(), out)  # fmt: skip
    procs = [ctx.Process(target=_worker, args=(wid, *args), daemon=True, name=f"netcreds-ng-{wid}")
             for wid in range(workers)]  # fmt: skip
    pending: list[deque[Event]] = [deque() for _ in range(workers)]
    marks = [0] * workers  # every event at or before this position has arrived, per worker
    results: list[RunStats | None] = [None] * workers
    try:
        for p in procs:
            p.start()
        while any(r is None for r in results):
            try:
                msg = out.get(timeout=1.0)
            except queue.Empty:
                dead = [p.name for p, r in zip(procs, results, strict=True) if r is None and not p.is_alive()]
                if not dead:
                    continue
                try:  # a worker may have queued its last message just before exiting
                    msg = out.get(timeout=1.0)
                except queue.Empty:
                    raise RuntimeError(f"parallel worker {', '.join(dead)} exited unexpectedly") from None
            kind, wid = msg[0], msg[1]
            if kind == "crash":
                log.debug("parallel worker %s traceback:\n%s", wid, msg[2])
                raise RuntimeError(f"parallel worker {wid} failed: {msg[2].strip().splitlines()[-1]}")
            if kind == "batch":
                marks[wid] = msg[2]
                pending[wid].extend(msg[3])
            else:  # done
                marks[wid] = _END + 1
                pending[wid].extend(msg[2])
                results[wid] = msg[3]
            _dispatch(session, pending, min(marks))
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
            p.join()
    for stats in results:
        assert stats is not None
        session.stats.merge(stats)
        session.stats.duplicates += stats.duplicates  # the engine's cross-plugin merges (the parent adds its own)


def _dispatch(session: Session, pending: list[deque[Event]], upto: int) -> None:
    """Publish every event at or before position ``upto``, in single-engine order."""
    ready: list[Event] = []
    for events in pending:
        while events and events[0][0] <= upto:
            ready.append(events.popleft())
    ready.sort(key=lambda e: e[:4])  # (position, phase, flow position, sequence): unique across workers
    pipeline = session.pipeline
    for event in ready:
        kind, payload = event[4], event[5]
        if kind == _FINDING:
            finding: Finding = payload
            pipeline.publish(finding)
        elif kind == _ERROR:
            if len(pipeline.errors) < 100:
                pipeline.errors.append(payload)
        else:
            session.notify_source(payload)
