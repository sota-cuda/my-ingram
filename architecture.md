# Ingram Architecture

> **Purpose:** This document is a maintained map of the Python code under `Ingram/`. It is intended to be the first reference when changing the scanner, adding a PoC, modifying fingerprinting, or working on the Dahua console integration.
>
> **Repository:** `sota-cuda/my-ingram`  
> **Reviewed:** 2026-09-22  
> **Scope:** `Ingram/`, plus the root launchers that call it.

## 1. What Ingram is

Ingram is a command-line network scanner for internet-connected cameras/NVRs. It expands individual IPs, CIDR ranges, and start-end ranges; probes configured ports; fingerprints HTTP services against rules in `Ingram/rules.csv`; runs product-specific verification/PoC plugins; records vulnerable and non-vulnerable targets; and optionally downloads camera snapshots after a successful verification.

The main scanner is launched by `run_ingram.py`. `targetMaker.py` is a separate helper that scrapes an IP-city range page and writes a target file. `Ingram/lib/DahuaConsole/` is a largely independent Dahua debug-console/client subsystem.

**Authorization boundary:** The scanner contains credential testing, authentication-bypass PoCs, credential extraction, and remote-device console operations. Use it only against systems for which the operator has explicit authorization.

## 2. Technology and dependencies

- **Language:** Python 3.
- **Concurrency:** `multiprocessing.Process` at the launcher, `gevent` greenlets/pool for target and port scanning, standard-library threads for status/snapshot workers, `ThreadPoolExecutor`, `Queue`, and locks.
- **HTTP:** `requests`, including `HTTPDigestAuth`; TLS certificate verification is disabled in many scanner/PoC requests because camera devices commonly use self-signed certificates.
- **Fingerprint parsing:** `lxml.etree`, regular expressions, response-body/header/status checks, and MD5 checksums.
- **Logging and terminal UI:** `loguru`, `colorama`, ANSI color helpers, generated ASCII-art logo, and a live status bar.
- **Cryptography:** `Crypto.Cipher.AES` for the Hikvision CVE-2017-7921 PoC; Dahua console code also includes custom DES/3DES and hashing routines and imports `pwntools`.
- **Network helpers:** `socket`, `ipaddress`, `IPy`, subprocess `ping`, and `urllib`-style HTTP requests.
- **Dahua console:** `pwntools` networking/packing helpers, sockets, JSON, HTTP/HTTPS, SSH relay support through pwntools, and custom protocol/authentication code.

No `README`, `requirements.txt`, `pyproject.toml`, setup file, test suite, Docker configuration, or CI workflow was present in the repository root at review time. Dependency installation therefore has to be inferred from imports or supplied by the operator.

## 3. Repository layout

```text
run_ingram.py                 Main scanner launcher and CLI orchestration
 targetMaker.py               Separate helper: scrape city IP ranges into targets-<code>.txt
Ingram/
  __init__.py                 Public package exports: get_config and Core
  config.py                   Default runtime configuration and CLI merge
  config-full.py              Alternate larger credential/port configuration; not imported by default
  core.py                     Main scan controller and result reporting
  data.py                     Input expansion, resume state, result files, snapshot queue
  rules.csv                   Product fingerprint rules
  pocs/                       Dynamically discovered product/CVE verification plugins
  utils/                      CLI, networking, fingerprinting, logging, UI, and common helpers
  lib/DahuaConsole/           Standalone Dahua protocol/debug console implementation
```

### Package entry points

- `Ingram/__init__.py` exposes `get_config` from `config.py` and `Core` from `core.py`.
- `run_ingram.py:run()` is the normal executable entry point. It applies gevent monkey-patching, prints the logo, parses arguments, creates output directories, configures logging, and runs `Core(config).run()` in a process.
- `Ingram/lib/DahuaConsole/Console.py:main()` is the separate Dahua console CLI entry point.
- `targetMaker.py:generate(code)` is a separate target-generation utility and is not part of the normal scan pipeline.

## 4. Scanner runtime flow

```text
run_ingram.py
  -> get_parse()                         Ingram/utils/argparse.py
  -> get_config(args)                    Ingram/config.py
       -> load Ingram/rules.csv
  -> Core(config).run()                  Ingram/core.py
       -> Data(config)                   Ingram/data.py
            -> read input / resume state
            -> expand targets with net.get_all_ip()
       -> SnapshotPipeline(config)       Ingram/data.py
       -> pocs.get_poc_dict(config)      dynamic PoC registration
       -> gevent pool over each IP
            -> _scan(target)
                 -> _scan_port(ip, port) for each configured port
                      -> port_scan()
                      -> fingerprint()
                           -> HTTP requests matched to rules.csv
                      -> PoC verify(ip, port)
                           -> results tuple on success
                      -> write results.csv / queue exploit()
       -> status_bar thread
       -> snapshot worker thread, unless disabled
       -> report()
```

### Target and task processing

`Data` is decorated with `common.singleton`. During initialization it opens append-mode result files, loads resume state from `<out_dir>/.<md5(in_file + out_dir)>` unless `--no-resume` is used, counts addresses in the input, and creates a generator that yields every IP. Input lines may be a single IP, CIDR, or `start-end` range; blank lines and lines beginning with `#` are skipped.

`Core._scan()` treats a target containing `:` as `ip:port`; otherwise it tests every configured port. Port jobs for one target are spawned with gevent. After all port jobs finish, `Data.done` is incremented and the state is periodically persisted every 20 completed targets.

### Fingerprinting

`config.get_config()` reads each non-empty line from `rules.csv` into a `Rule(product, path, val)` namedtuple and builds `config.product`. `utils.fingerprint.fingerprint()` groups requests by path, caches successful HTTP 200 responses, and evaluates rules through `_parse()`.

Supported rule predicates are:

- `md5=` — MD5 of response bytes
- `title=` — substring of the HTML title
- `body=` — substring in body descendants
- `headers=` — substring in response headers
- `status_code=` — exact status code
- `&&` combines predicates with logical AND

The first matching product is returned. The current rules identify products such as `avtech`, `axis`, `cctv`, `dahua`, `dlink-dcs`, `dvr`, `geovision`, `hikvision`, `instar`, `ipcamera`, `netwave`, `nuuo`, `reecam`, `tenda`, `uniview`, and `xiongmai`.

## 5. Configuration and command-line contract

`Ingram/utils/argparse.py:get_parse()` defines the normal scanner CLI:

| Option | Meaning | Default |
|---|---|---|
| `-i`, `--in_file` | Required target file | None |
| `-o`, `--out_dir` | Required output directory | None |
| `-p`, `--ports` | Explicit ports, one or more integers | `config.py` port list |
| `-t`, `--th_num` | Gevent/thread worker count | `150` |
| `-T`, `--timeout` | Network request/socket timeout | `3` |
| `-D`, `--disable_snapshot` | Do not run snapshot exploitation | false |
| `--debug` | Include all configured log levels | false |
| `--no-resume` | Ignore saved progress state | false |

`config.py` supplies default users, passwords, ports, a single random user-agent, output filenames, and empty WeChat fields. The config object is a namedtuple created from the mutable module-level `_config` dictionary. CLI values overwrite non-`None` defaults.

`config-full.py` has the same schema but a substantially larger credential and port list. It is an alternate copy, not a runtime-selected profile: `run_ingram.py` imports `get_config` through `Ingram/__init__.py`, which points to `config.py`.

## 6. Output files and resume behavior

Given `--out_dir <dir>`, the launcher creates `<dir>` and `<dir>/snapshots` when the output directory does not already exist. The runtime uses:

- `<out_dir>/log.txt` — Loguru output configured by `utils/log.py`.
- `<out_dir>/results.csv` — successful PoC results. Rows normally begin with `ip,port,product,user,password,poc_name`; PoCs may append additional fields, so consumers should not assume a fixed row length beyond the first six fields.
- `<out_dir>/not_vulnerable.csv` — fingerprinted products for which no PoC verified successfully, normally `ip,port,product`.
- `<out_dir>/snapshots/` — images downloaded by PoC `exploit()` methods.
- `<out_dir>/.<taskid>` — resume state containing `done,found,runned_time`.

`Core.report()` reads `results.csv`, groups rows using `i[2]` as the device/product and `i[-1]` as the vulnerability/PoC name, and prints a terminal report.

## 7. Core modules

### `Ingram/config.py`

- Owns the default `_config` dictionary.
- Calls `net.get_user_agent()` once during module import.
- Loads `rules.csv` on every `get_config()` call and mutates the shared `rules` set/product map.
- Returns a namedtuple named `config`.
- Contains credential and port defaults; treat changes here as scan-behavior changes.

### `Ingram/core.py`

`Core` is a singleton controller. It owns `Data`, `SnapshotPipeline`, and the product-to-PoC dictionary.

- `_scan_port()` checks a port, fingerprints the HTTP service, executes every registered PoC for the matching product, records successful results, and queues snapshots.
- `_scan()` handles an IP or `ip:port`, runs port jobs, and updates progress.
- `finish()` waits for all targets and queued snapshot tasks.
- `report()` prints aggregate results.
- `run()` starts status/snapshot threads, scans the generator through a gevent pool, waits for the status bar, and reports.

### `Ingram/data.py`

- `Data`: singleton state/input/result manager with thread-safe counters and file writes.
- `SnapshotPipeline`: bounded queue (`th_num * 2`) plus `ThreadPoolExecutor`; receives `(poc.exploit, results)` and calls the exploit function in worker threads.
- `POCTemplate._snapshot()` is the common image downloader used by most PoCs.

### `Ingram/utils/`

- `argparse.py` — scanner CLI parsing.
- `net.py` — IP-range length/iteration and static/random user-agent selection; imports `IPy`, `requests`, and `lxml` support for the user-agent scraper.
- `port_scan.py` — TCP `connect_ex()` port check.
- `fingerprint.py` — HTTP rule matching and response caching.
- `common.py` — OS detection, singleton decorator, bounded `IngramThreadPool`, and subprocess helper `run_cmd()`.
- `alive_check.py` — platform-aware two-packet `ping` wrapper; currently not referenced by the main scan flow.
- `status_bar.py` — live progress display and estimated remaining time.
- `timer.py` — timestamps, formatted time, decorator, and duration formatting.
- `log.py` — Loguru file handler configuration and debug filter.
- `color.py` — colorama-backed `ColorPalette`; exports the singleton `color` object.
- `logo.py` — random ASCII font selection and terminal-width-aware logo generation.
- `__init__.py` — package marker/re-export surface used by relative imports.

## 8. PoC plugin architecture

`Ingram/pocs/__init__.py` dynamically imports every file in its directory except `__init__.py` and `base.py`. Each plugin module defines a subclass of `POCTemplate` and ends with `POCTemplate.register_poc(PluginClass)`. `get_poc_dict(config)` instantiates every registered class and groups instances by `poc.product`.

The plugin contract is:

```python
class MyPoc(POCTemplate):
    def verify(self, ip, port):
        # return (ip, port, product, user, password, poc_name) on success
        # return None on failure
        ...

    def exploit(self, results):
        # normally download one or more snapshots and return image count
        ...
```

`POCTemplate` creates a persistent `requests.Session`, applies the configured user-agent, defines vulnerability metadata fields, and provides `_snapshot(url, img_file_name, auth=None)`. The base `exploit()` is only a placeholder.

Current PoC modules are organized by device/vendor and vulnerability:

- Weak-password checks: `avtech-weak-password.py`, `axis-weak-password.py`, `dahua-weak-password.py`, `dvr-weak-password.py`, `ezviz-weak-password.py`, `geovision-weak-password.py`, `hanwha-weak-password.py`, `hikvision-weak-password.py`, `instar-weak-password.py`, `ipcamera-weak-password.py`, `netwave-weak-password.py`, `nuuo-weak-password.py`, `reecam-weak-password.py`, `reolink-weak-password.py`, and `xiongmai-weak-password.py`.
- Authentication bypass, disclosure, or CVEs: `cve-2017-14514.py`, `cve-2017-7921.py`, `cve-2018-17240.py`, `cve-2018-6479.py`, `cve-2018-9995.py`, `cve-2020-25078.py`, `cve-2021-33044.py`, `cve-2021-33045.py`, `cve-2021-36260.py`, `cve-2021-40655.py`, `cve-2022-23459.py`, `cve-2022-2471.py`, `cve-2022-28171.py`, `cve-2022-30563.py`, `cve-2023-26801.py`, `cve-2023-27359.py`, `cve-2023-28808.py`, `cve-2023-45222.py`, `cve-2023-47221.py`, `cve-2024-39943.py`, `uniview-disclosure.py`, and `xiongmai-bypass.py`.
- Disabled/experimental-looking module: `dahua-disabled.py`; because discovery imports all non-base Python files, filename-based exclusion is not currently implemented for this module.

Examples of implemented behavior:

- `hikvision-weak-password.py` loops through configured credentials against `/ISAPI/Security/userCheck`, then uses HTTP Digest authentication to enumerate channels and download `/ISAPI/Streaming/channels/<channel>01/picture`.
- `dahua-weak-password.py` posts `global.login` JSON to `/RPC2_Login`, then downloads `/cgi-bin/snapshot.cgi` with digest authentication.
- `cve-2017-7921.py` verifies Hikvision information disclosure, decrypts/extracts credentials using AES plus XOR, and downloads an ONVIF snapshot.
- `uniview-disclosure.py` parses an unauthenticated XML response and decodes reversible password strings; its `exploit()` currently returns `None`.

When adding a PoC, ensure the fingerprint product exactly matches a product key loaded from `rules.csv`, use relative import `.base`, register the class at module import time, return the expected six-field result tuple, and handle request/XML/JSON errors without terminating the whole scan.

## 9. DahuaConsole subsystem

`Ingram/lib/DahuaConsole/` is not wired into `Core` or `run_ingram.py`. It is a separate command-line/debug client with its own import style (many modules use `from utils import *` and are intended to be run from that directory).

### Layering

```text
Console.py:main / DebugConsole
  -> Servers
       -> DahuaEvents
            -> DahuaConnect
                 -> DahuaFunctions (dahua.py)
                      -> Network (net.py)
  -> PwdManager / dahua_logon_modes.py
  -> relay.py for SSH-relayed connections
  -> eventviewer.py for local event viewing
```

- `Console.py` parses protocol, host, credentials, relay, debug, dump/restore, event, and multi-host options, then provides an interactive command dispatcher.
- `connection.py:DahuaConnect` validates hosts/ports, creates `DahuaFunctions`, tracks multiple sessions in `dhConsole`, and reconnects failed sessions up to ten times at 30-second intervals.
- `dahua.py:DahuaFunctions` is the device-level API/protocol layer built on `Network`.
- `net.py:Network` contains Dahua network/protocol operations; inspect this module before modifying DHIP/DVRIP behavior.
- `dahua_logon_modes.py` builds Dahua login payloads for `dvrip`, `3des`, DHIP/HTTP(S), WSSE, ONVIF, digest, and bypass/test modes, and contains Dahua hashing plus custom DES/3DES implementations.
- `pwdmanager.py:PwdManager` stores host records in a local `dhConsole.json`, including derived credential hashes and connection metadata.
- `servers.py:Servers` provides a local UDP event listener on port `43210` and TCP event fan-out server on `127.0.0.1:43211`, plus daemon restart handling.
- `events.py:DahuaEvents` parses event JSON and handles reboot, alarm, login-failure, reset, and device/VTO/VTH event types.
- `eventviewer.py` connects to the local TCP event server and prints repaired event JSON.
- `relay.py` supports SSH relay setup and contains `DahuaHttp` for HTTP/HTTPS JSON API communication, automatic HTTP/HTTPS fallback, redirects, cookies, and event streams.
- `utils.py` supplies pwntools imports, terminal colors, JSON repair (`fix_json`), host/port validation, IP packing, and shared event-server constants.

The subsystem has legacy/non-package imports and assumptions about the current working directory. Do not refactor it into package-relative imports without testing every console entry path.

## 10. Operational caveats and maintenance hazards

1. **No dependency lockfile:** Import requirements are not declared. Create a requirements/pyproject file before making deployment reproducible.
2. **Mutable global config:** `_config`, `rules`, and `product` persist between calls to `get_config()`. Repeated calls can retain previous CLI values and rules.
3. **Output-directory creation:** `run_ingram.py` only creates `snapshots` inside the branch where `out_dir` is newly created. Supplying an existing output directory without `snapshots/` can break `SnapshotPipeline`.
4. **CLI option naming:** argparse stores `--no-resume` as `no_resume` through argparse's underscore conversion, which matches `Data._load_state_from_disk()`.
5. **Colon parsing:** `Core._scan()` splits targets on `:`, so IPv6 input is not supported by the target parser.
6. **Fingerprint assumptions:** `_parse()` assumes expected HTML/body/title nodes exist; malformed pages can produce logged exceptions and missed fingerprints.
7. **Snapshot completion:** `SnapshotPipeline.process()` polls the queue and worker count; changing `Core.finish()` or task accounting can cause premature completion or hangs.
8. **Process/thread/gevent interaction:** gevent monkey-patching occurs in `run_ingram.py` before imports. Changes to import order or concurrency primitives can change behavior.
9. **Result parsing:** `Core.report()` assumes product is field 3 and PoC name is the last field. Preserve that shape when changing result rows.
10. **Credential and secret exposure:** Default credential lists and successful credentials are stored in source/results. Avoid committing generated output, `dhConsole.json`, logs, or scan results.
11. **DahuaConsole import model:** The console modules are not a conventional package and use wildcard/local imports. Run/test them from their expected directory.
12. **Security-sensitive requests:** Many requests use `verify=False` and may contact arbitrary targets. Keep authorization and safe-scope checks outside the tool workflow.

## 11. Recommended change locations

| Change | Primary files |
|---|---|
| Add a CLI option | `Ingram/utils/argparse.py`, then consume the field in `config.py`, `core.py`, or `data.py` |
| Change default ports/credentials | `Ingram/config.py` (or deliberately replace/merge `config-full.py`) |
| Add/edit a fingerprint | `Ingram/rules.csv`, then validate `Ingram/utils/fingerprint.py` |
| Add a product PoC | New `Ingram/pocs/<name>.py`, subclass/register `POCTemplate` |
| Change target expansion/resume | `Ingram/data.py`, `Ingram/utils/net.py` |
| Change scan concurrency | `run_ingram.py`, `Ingram/core.py`, `Ingram/data.py` |
| Change result/report format | `Ingram/data.py`, `Ingram/core.py` |
| Change snapshots | `Ingram/pocs/base.py`, `Ingram/data.py`, individual PoC `exploit()` methods |
| Change console login/hash behavior | `Ingram/lib/DahuaConsole/dahua_logon_modes.py`, `pwdmanager.py`, `connection.py` |
| Change Dahua device APIs | `Ingram/lib/DahuaConsole/dahua.py`, `net.py`, `relay.py` |
| Change Dahua event handling | `servers.py`, `events.py`, `eventviewer.py` |

## 12. Verification checklist

Before merging scanner changes:

1. Run Python compilation over `Ingram/` and the root launchers.
2. Run unit-level tests for IP expansion, fingerprint predicates, result-row formatting, and resume state where available.
3. Test a single authorized target with a narrow input and one explicit port before a range scan.
4. Test both `--disable_snapshot` and snapshot-enabled paths.
5. Test a fresh output directory and an existing resumable output directory.
6. For a new PoC, test no-match, match, malformed response, timeout, and exploit/snapshot failure paths.
7. For DahuaConsole changes, exercise the exact intended CLI working directory and protocol mode; do not assume the scanner's package import path applies.

## 13. Minimal scanner invocation

The repository does not declare installation commands, but the runtime invocation is:

```bash
python3 run_ingram.py --in_file targets.txt --out_dir output/
```

Useful variants:

```bash
# Narrow authorized test
python3 run_ingram.py -i one-target.txt -o output -p 80 443 -t 10 -T 3 -D

# Fresh run with detailed logging
python3 run_ingram.py -i targets.txt -o output --no-resume --debug
```

At minimum, the environment must provide Python 3 and the imported third-party packages used by the selected path, including `gevent`, `loguru`, `requests`, `lxml`, `IPy`, `colorama`, `pycryptodome`/`Crypto`, and (for DahuaConsole) `pwntools`.
