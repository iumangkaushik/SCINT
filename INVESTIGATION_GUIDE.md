# How Real Investigators Trace Fraudsters

### A field-oriented companion to SCINT · GPCSSI 2026 · Gurugram Police

> **Why this exists:** Scammers almost never use their real identity. The phone is a fake/forged-KYC SIM, the "Aadhaar" shown at onboarding is stolen or photoshopped, and the bank account is a *mule* (rented, bought, or opened in a victim's name). So the front-facing identifiers are **dead ends by design**. Real cases are not solved by trusting those fields — they are solved by attacking the few things a criminal *cannot* easily fake, using **lawful process**.

---

## The golden rule

You do **not** hack the suspect to get their data. Unauthorised access is itself a crime (IT Act §66), it tips the suspect off, and any evidence obtained that way is inadmissible in court. Every technique below works through **legal authority** — notices to telecoms and banks, court-ordered disclosure, and inter-agency requests. The investigation closes in on the criminal's *mistakes*, not their disguises.

---

## The four chokepoints a fraudster can't fake

### 1. The money trail (the strongest thread)

A fake SIM costs nothing, but stolen money has to physically **come out** somewhere. It is moved through layers of mule accounts (this is called *layering*), but eventually it is withdrawn as cash, cashed out through a wallet, or converted to crypto/gift cards. That exit is the weak point.

- **Follow it forward** through each mule account via legal notice to the banks (in India: a notice under §94 BNSS, formerly §91 CrPC).
- **The cash-out point** yields real evidence: ATM CCTV footage, the KYC on the final wallet, the device/IP that authorised the last transfer.
- **Mule-account operators** are often students or low-income individuals who "rented" their account — they are traceable and frequently flip to identify the handler.

> **Investigator's instinct:** ignore where the money came *from* (the victim) and chase where it's going *to*. The last hop before cash is where the real person touches the system.

### 2. The device fingerprint (beats the fake SIM)

A fake SIM placed inside a **real handset** still exposes that handset's **IMEI**. The SIM is disposable; the phone often isn't.

- If one **IMEI** appears across many fraudulent SIMs, you have just linked many "different people" to **one device**.
- **CDR (Call Detail Records)** and **IPDR (IP Detail Records)** from the telecom expose the IMEI, the cell towers (approximate location), call/SMS patterns, and data sessions.
- App logins leak **device IDs, OS versions, and IP addresses** — request these from the platform via legal process.

### 3. Reused patterns / linkage analysis (this is what a tool like SCINT is *for*)

Even when every document is fake, criminals are lazy and run at volume, so they **reuse** things:

- the same recovery email or alternate phone,
- the same UPI handle that also appears on an old OLX/classified post,
- the same withdrawal ATM or pickup location,
- the same scam *script*, language, and active hours.

Correlating dozens of fake identities back to **one operator** is the entire game. **This is the legitimate purpose of a correlation tool** — not to trust any single record, but to find the one human behind many masks. SCINT's "link records + score" design models exactly this idea.

### 4. The physical point of sale / pickup

Every fake SIM was **activated by a real retailer** using forged documents — and that retailer, the activation location, and the bulk-activation pattern are all traceable. Large SIM-fraud rings are routinely cracked through the point-of-sale agent who mass-activated the connections. Likewise, delivery drops, rented "offices," and cash mules give you a physical person to question.

---

## The investigator's toolkit (lawful)

| Source | What it gives you | How you get it |
|---|---|---|
| **CDR / IPDR** (telecom) | IMEI, towers, IPs, contacts, sessions | Legal notice to TSP |
| **Bank / UPI / wallet records** | Mule chain, KYC, IPs, cash-out point | §94 BNSS notice to bank/PSP |
| **ATM / shop CCTV** | A face at the cash-out | Request to bank / premises |
| **Platform logs** (Google, Meta, Telegram) | Device IDs, login IPs, recovery info | Legal request / MLAT if foreign |
| **OSINT** | Reuse of number/UPI/email elsewhere | Open sources — fully legal |
| **NCRP / I4C / CEIR** | Linked complaints, blocked IMEIs | Inter-agency portals |

### Key Indian resources

- **NCRP** — National Cyber Crime Reporting Portal (`cybercrime.gov.in`)
- **I4C** — Indian Cyber Crime Coordination Centre
- **CEIR** — Central Equipment Identity Register (blocks/tracks stolen IMEIs)
- **CERT-In** — incident response and infrastructure data
- **CCTNS** — Crime and Criminal Tracking Network & Systems (case linkage)
- For foreign-hosted infrastructure: **MLAT** (Mutual Legal Assistance Treaty) requests

---

## Putting it together — a typical trace

1. **Victim reports** a UPI scam; you have only a fake number and a UPI ID.
2. **Bank notice** reveals the money hopped through 3 mule accounts in 40 minutes.
3. The **third mule** withdrew cash at an ATM → pull **CCTV** + the **IP/device** that authorised it.
4. That device's **IMEI** also logged into **two other mule accounts** from other open cases → linkage.
5. **OSINT** ties the recovery email to a Telegram handle advertising "bank accounts for rent."
6. **CDR** on the linked number puts the handset near a specific locality at withdrawal times.
7. You now have a **real person and a physical area** — built entirely from the criminal's mistakes, not their fake IDs.

---

## What this means for SCINT

SCINT is a **triage and correlation demonstrator**. Its job isn't to trust the (dummy) Aadhaar or bank fields — it's to show how aggregating weak signals across many records surfaces the high-risk operator behind multiple fake identities, so a human investigator knows where to point the *lawful* tools above. That framing — **correlate signals, then pursue chokepoints through due process** — is the professional, court-defensible way to catch fraudsters who hide behind fake numbers and stolen IDs.

> ⚠️ Educational material for the GPCSSI 2026 internship. Describes lawful investigative methodology only. All data in this project is fictional.
