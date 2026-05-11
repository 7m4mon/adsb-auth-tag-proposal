# Simple ADS-B Authenticity Tag Proposal

Date: 11 May 2026  
Author: 7M4MON

## Overview

This is a proposal for an additional authentication frame intended to help mitigate ADS-B spoofing.

ADS-B is a system in which an aircraft broadcasts its own position, altitude, speed, identification information, and other data to surrounding aircraft and ground stations. However, current ADS-B messages themselves do not include a cryptographic authentication mechanism.

As a result, from a purely technical point of view, it is relatively easy to build a device that transmits ADS-B-like signals. A malicious transmitter could potentially create a “non-existent aircraft” or make an aircraft appear to be in a different location.

This is a problem.

The purpose of this proposal is to provide a lightweight mechanism that can support the following statement:

> “At least at that time, the legitimate aircraft was present in that airspace.”

This document describes an idea for an additional authentication frame to support that goal.

---

## Background

There are already several serious proposals for ADS-B spoofing countermeasures.

Examples include:

- ADS-B authentication using TESLA
- Aircraft certificates using PKI
- Additional data transmission using phase overlay
- CABBA: Compatible Authenticated Bandwidth-efficient Broadcast protocol for ADS-B
- Secure Authentication of ADS-B Aircraft Communications using Retroactive Key Publication
- IETF draft: ADS-B Authentication

In contrast, the idea described in this repository is a much simpler approach.

---

## Basic Idea

The basic idea is to add one new type of ADS-B frame and place a short authentication value inside it.

Existing position frames, velocity frames, aircraft identification frames, and other standard ADS-B messages are not modified.

For compatibility, the additional authentication frame uses the same overall structure as the current ADS-B Extended Squitter frame:

```text
DF17 ADS-B Extended Squitter

| DF | CA | ICAO Address | ME Field | PI |
```

Within the ME field, a reserved Type Code value is tentatively assigned and treated as an authentication tag message.

---

## Tentative Frame Assignment

This proposal does not define a new DF or CA value. Instead, it uses the existing 1090ES ADS-B frame structure.

The tentative assignment is as follows:

| Field | Value |
|---|---:|
| DF | 17 |
| CA | Existing transponder capability value |
| ME Type Code | 24 |
| PI | Standard Mode S parity |

Type Codes 23 to 27 are reserved. In this proposal, Type Code 24 is tentatively used as `Proposed Authenticity Tag`.

However, while the full ME field is 56 bits, the first 5 bits are used as the Type Code. Therefore, only 51 bits remain available for the timestamp and HMAC.

This proposal assigns those bits as follows:

| Field | Bits | Description |
|---|---:|---|
| Type Code | 5 | 24: Proposed Authenticity Tag |
| Timestamp | 27 | 1-second resolution, approximately 4.25-year cycle |
| Truncated HMAC | 24 | Single-attempt forgery probability of 1 / 16,777,216 |

```text
ME field: 56 bits

+-----------+---------------------------+------------------------+
| Type Code | Timestamp                 | Truncated HMAC         |
| 5 bits    | 27 bits                   | 24 bits                |
+-----------+---------------------------+------------------------+
```

---

## HMAC Input

The HMAC is calculated using a secret key assigned to each aircraft or transmitter.

Example:

```text
HMAC = Truncate24(HMAC-SHA256(secret_key, message))
```

The MAC input is as follows:

```text
DF
CA
ICAO address
ME Type Code
Timestamp
```

---

## What This Scheme Is Intended to Prove

This scheme is intended to prove the following:

> At that time, the legitimate transmitter possessing the secret key generated this message.

Furthermore, if an internet-connected receiver compares the received information with public key information, certificates, and the reception time, it can increase confidence in the following statement:

> The aircraft was present in that airspace at that time.

---

## Internet Connectivity Is Required on the Receiver Side

This scheme assumes that the receiver can obtain the following information via the internet:

- Public key information corresponding to the aircraft or transmitter
- Certificates
- Key IDs
- Revocation information
- Key update information

In other words, this is not a scheme that can be completed entirely by a fully offline receiver.

The intended use case is verification by internet-connected ground receiving stations or network-connected ADS-B receiver systems.

---

## Why 27-bit Timestamp + 24-bit HMAC?

A 27-bit timestamp with 1-second resolution lasts for approximately 4.25 years.

```text
2^27 seconds = 134,217,728 seconds
134,217,728 / 60 / 60 / 24 / 365 ≒ 4.25 years
```

The single-attempt forgery probability of a 24-bit HMAC is:

```text
1 / 2^24 = 1 / 16,777,216
```

A 24-bit HMAC is short from a cryptographic point of view. However, this scheme is not intended to provide full-scale cryptographic authentication. Its purpose is lightweight spoofing deterrence while maintaining backward compatibility with existing ADS-B.

In the case of ADS-B, an attacker attempting to brute-force the HMAC would need to transmit a large number of fake ADS-B frames on 1090 MHz.

This would be close to jamming or polluting the 1090 MHz band in practice.

Such large-scale attempts could likely be detected by methods such as:

- A large number of authentication failures for the same ICAO address
- Abnormal frame density
- Unnatural reception patterns across multiple receiving stations

Therefore, while increasing the HMAC length is important, old replay attacks using previously recorded legitimate messages may be a more troublesome realistic threat.

---

## The 4.25-Year Replay Problem and Key Rotation

A 27-bit timestamp wraps around after approximately 4.25 years.

Therefore, in theory, the following replay attack is possible:

> An attacker records a legitimate message and retransmits it approximately 4.25 years later when the same timestamp value occurs again.

As a countermeasure, the aircraft-specific key pair or HMAC key should be updated at an interval shorter than the timestamp cycle.

For example, if keys are updated once per year, a message from a previous timestamp cycle will fail HMAC verification under the current key.

Therefore, the following condition should be satisfied:

```text
Key update interval < Timestamp cycle
```

From this point of view, a 27-bit timestamp is easier to manage than a 24-bit timestamp, which has a cycle of approximately 194 days.

---

## Key Leakage and Updates

This scheme assumes that each aircraft or transmitter has its own secret key.

If the secret key is stolen, any HMAC generated using that key can no longer be trusted.

In that case, the following actions are required:

- Secret key revocation
- Key pair update
- Public key information update
- Distribution of revocation information

In other words, a key management mechanism is essential. It would need to be combined with mechanisms such as a public key infrastructure, certificates, and revocation lists.

---

## Compatibility with Existing ADS-B

This proposal does not modify existing ADS-B messages.

A normal ADS-B receiver may not understand the additional authentication frame, but it can still receive the existing position, velocity, identification, and other standard frames as before.

Therefore, backward compatibility is maintained.

```text
Existing receiver:
  Reads only normal ADS-B frames

Compatible receiver:
  Reads normal ADS-B frames and the additional authentication frame
  Verifies authenticity using information obtained via the internet
```

---

## Why Not Apply an HMAC to the Previous Message?

One possible idea to increase the effective amount of authenticated information is:

```text
Authentication frame = HMAC of the immediately preceding ADS-B message
```

However, ADS-B is a one-way broadcast system. There is no ACK and no retransmission.

Therefore, the receiver cannot be assumed to have successfully received the immediately preceding message.

Adding a sequence number could be considered, but that would compromise compatibility with existing frames.

---

## What This Scheme Can Do

- Deter simple ADS-B spoofing
- Deter old replay attacks
- Confirm that a message was generated by a legitimate transmitter
- Enable authenticity verification by internet-connected receivers
- Maintain backward compatibility with existing ADS-B

---

## Conclusion

Several full-scale ADS-B spoofing countermeasures have already been proposed.

However, many of them involve mechanisms such as TESLA, PKI, or phase overlay, and their implementation, standardization, and operation would require significant cost and effort.

This document proposes a simpler approach:

```text
Add one authentication frame type to ADS-B
Use the existing DF=17 ADS-B Extended Squitter structure
Tentatively use reserved ME Type Code 24
Use 27-bit timestamp + 24-bit truncated HMAC as the ME payload
Do not modify existing ADS-B frames
Let internet-connected receivers verify the tag using public key information
Rotate keys at an interval shorter than the timestamp cycle
```

This may be worth considering as a lightweight additional authentication method that maintains compatibility with existing ADS-B while helping deter simple spoofing and old replay attacks.
