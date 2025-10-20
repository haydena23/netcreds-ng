from __future__ import annotations
from collections import OrderedDict
from typing import List, Any

telnet_prompts: OrderedDict[str, str] = OrderedDict()
mail_auths: OrderedDict[str, List[int]] = OrderedDict()
ntlm_challenges: OrderedDict[int, str] = OrderedDict()

MAX_STATE_ENTRIES = 100

def clean_state_dict(state_dict: OrderedDict[Any, Any]) -> None:
    """Removes the oldest entries from a state dictionary if it exceeds the max size."""
    while len(state_dict) > MAX_STATE_ENTRIES:
        state_dict.popitem(last=False)