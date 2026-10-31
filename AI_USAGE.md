# AI Usage Disclosure

**Summary:** Claude wrote most of SCINT's code. My part was choosing the problem, deciding what the tool should do, running and testing it, deploying it, and — before submitting — having it audited and fixing what the audit found. I have studied the security logic so I can explain and change it myself.

## 1. Which AI tools did you use?

**Claude (Anthropic)** — the only AI tool I used. The 31 October pre-submission review used Claude Code.

## 2. How did AI assist you?

- **Building SCINT (June–September 2026):** I described the tool I wanted — a scam cyber-intelligence tool for the fraud problem covered in the GPCSSI 2026 internship — and Claude wrote most of the code: the CLI, the Flask dashboard, the API wrappers and the dummy-data generator. I ran it, tested it, asked for fixes and new features, deployed it on Render and published it on GitHub.
- **Reviewing it (31 October 2026):** before submitting, I had Claude Code audit the repository for anything that could get it rejected (secrets, malicious functionality, real personal data) and check the scoring for false positives. It then fixed the problems, added unit tests and sample outputs, and filled the documentation gaps.

## 3. Which parts were generated or substantially suggested by AI?

Who did what, by area of work:

| Area of work | Who |
|---|---|
| Choosing the problem (scam / cyber-fraud intelligence, from GPCSSI 2026) | **Me** |
| Deciding what SCINT should do (features, inputs, outputs) | **Me**, with suggestions from Claude |
| Writing the code (`scint.py`, `app.py`, `live_intel.py`, `db.py`, `report_*.py`, `templates/`, `generate_dataset.py`) | **Claude** wrote most of it; I asked for changes and fixes |
| Running it, testing it, reporting what broke | **Me** |
| Deploying to Render and publishing on GitHub | **Me** |
| 31 October security audit, fixes, `tests/`, `samples/`, README security sections | **Claude Code**, reviewed and approved by me |
| Demo video and explaining the project | **Me** |

## 4. What mistakes, insecure suggestions or incorrect assumptions did AI make?

The 31 October audit found these problems in the AI-generated code:

| Problem | Why it mattered |
|---|---|
| `app.run(debug=True)` | The Werkzeug debugger allows code execution from the browser if the port is reachable |
| One VirusTotal engine added +20 risk | Single-engine detections are a common false positive; an innocent IP could be pushed toward MEDIUM |
| Sharing an IP with any flagged number added risk | Mobile carriers use CGNAT, so this would link thousands of unrelated subscribers to a fraudster |
| Raw user input placed in API URL paths | Input like `8.8.8.8/../x` could alter the request path, and private IPs were sent to third-party APIs |
| Phone number used directly in the report filename | Input like `../../x` could write outside `reports/` |
| Duplicated `import live_intel` block | Harmless, but the second block silently overwrote the first |

Mistakes made during the 31 October session itself:

- **Wrong assumption:** Claude first told me I had no existing security project, because it had only searched one folder. I pointed it to SCINT.
- **Garbled sample outputs:** the first sample-output files were unreadable (Windows console encoding) and had to be regenerated.
- **Silent test failure:** the first test run found 0 tests because `tests/__init__.py` was missing, which could have been mistaken for a pass.

## 5. How did you manually validate the generated code or output?

- `python -m unittest -v`: 10 tests pass (`samples/output_tests.txt`), covering true positives, true negatives and each false-positive rule. I re-ran them myself for the demo video.
- Ran the CLI on known values and checked the bands: `9898329822` → HIGH, `9009897600` → LOW, `192.168.1.10` → rejected with no API calls.
- Checked the dummy data before accepting the shared-gateway threshold of 10: fraud rings share an IP between 3 numbers, clean ISP IPs are shared by 18–28, so 10 keeps rings flagged without linking innocent subscribers.
- Searched the full git history for API-key-shaped strings and for a committed `.env`: none found.
- Tried other phone formats and found a real limitation: `+91 9898329822` scores 0. It is documented in the README instead of hidden.

## 6. What did you change after reviewing the AI-generated work?

- Corrected Claude's wrong assumption that I had no existing project and had it review SCINT instead of building something new.
- Asked for everything that could cause rejection to be removed before submitting, rather than submitting the code as it was. That led to the six fixes above, and to deleting a setup note that contained my personal email and local file paths.
- Kept the `+91` phone-format false negative visible as a documented limitation instead of quietly patching around it.

## 7. Which part of the final project can you confidently explain without AI assistance?

- **The problem and the design:** why correlating identity, bank, telecom and crime records catches what one database alone misses, and why the restricted government feeds are simulated while public threat feeds are queried live
- **The phone lookup, end to end:** input → four database lookups keyed on the phone number → weighted signals → score capped at 100 → LOW / MEDIUM / HIGH band → recommended action
- **`score_phone_quiet()` in `scint.py`:** every weight and threshold, the cross-database bonus, and the fraud-ring (shared-IP) signal
- **`is_shared_gateway()`:** why CGNAT and public Wi-Fi make a shared IP weak evidence, and the 10-number threshold
- **`live_ip_score()` in `live_intel.py`:** how AbuseIPDB, VirusTotal and ip-api results combine into one score, and why one VirusTotal engine is not trusted (`VT_MIN_ENGINES = 2`)
- **`validate_public_ip()`:** how the `ipaddress` module rejects malformed, private, loopback and CGNAT addresses before any API call
- **Secrets handling:** `.env` + `load_dotenv()` + `.gitignore`, and `.env.example` as the template
- **The tests:** how `unittest.mock` replaces the live APIs so the tests run offline
- **The limitations:** the `+91` false negative, and what the false-positive rules trade away
