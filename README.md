# WORK IN PROGRESS

Python3 port of the `net-creds` tool made by [Dan McInerney](https://github.com/DanMcInerney/net-creds)

### HOW-TO
```bash
cd ./netcreds-ng/src
sudo python -m netcreds_ng --help
```

### Feature Ideas
#### Deepen Core Functionality
* Expand Protocol Coverage
  * Databases
    * MySQL
    * MariaDB
    * PostgreSQL
  * Code & CI/CD
    * Git protocol
    * Jenkins
  * Industrial/IoT
    * Modbus
    * MQTT
  * VoIP
    * SIP
  * Cloud & DevOps
    * AWS/GCP/Azure API keys
    * Docker/Kubernetes
  * Cacheing Systems
  * Redis
* Deepen All Existing Parsers
  * HTTP
    * Extract session cookies
    * API keys
    * JWTs
    * Look through JSON/XML bodies
  * FTP/SMB/etc File Carving
    * Identify magic bytes/file name, extract file for later analysis
* Session Management
  * Allow live capture to be paused/resumed
* Allow user to provide server's private SSL/TLS key to decrypt traffic

#### Intelligence
* Credential Correlation
  * Track credentials
  * Password Reuse across multiple protocols
  * Username correlation across multiple profiles to start building profile of activity
* Attack Path Mapping
* Heuristic and Behavioral Analysis
  *  Entropy Analysis and byte-frequency distribution
  *  Client/Server Dialogue Analysis
  *  Password spray detection
  *  Brute Force detection
  *  Anomalous Protocol Detection
* Risk Scoring/Triage
  * Calculate severity score?
* Password Composition Analysis

#### Ecosystem
* Webhook Support
* Discord notification bot
* Enhanced Reporting
  * HTML Report on close
  * Format report

#### Enhanced Dashboard
* Dedicated "Alerts" panel
* Sparklines for packets-per-second