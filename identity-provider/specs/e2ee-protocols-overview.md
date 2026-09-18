# E2EE protocols — an explainer for Pina'i

A walkthrough of X3DH, Double Ratchet, Sender Keys, and MLS — what each one
solves, how it works, and where they fit together. Aimed at someone choosing
an E2EE design for a federated chat system.

## Vocabulary you'll see throughout

- **Forward secrecy** — if today's keys leak, yesterday's messages stay safe. Achieved by deriving fresh keys per message and deleting the old ones.
- **Post-compromise security (PCS)** *(a.k.a. future secrecy / break-in recovery)* — if today's keys leak, the system *recovers* on its own as more messages flow. Achieved by mixing in fresh randomness (typically via Diffie-Hellman steps) periodically.
- **Asynchronous** — the protocol works even when the recipient is offline at the moment the sender encrypts.
- **Deniability** — a third party can't cryptographically prove that *this specific person* sent *this specific message*.
- **AEAD** — Authenticated Encryption with Associated Data. The symmetric primitive (AES-GCM, ChaCha20-Poly1305) every chat protocol ends up using to actually encrypt the bytes. Provides confidentiality + integrity.
- **DH (Diffie-Hellman)** — two parties exchange public keys; both can compute a shared secret without ever sending it. The classical key-agreement trick that everything else is built on.
- **KDF (Key Derivation Function)** — given an input secret, deterministically derive new keys. Lets you "ratchet" forward without communicating.

---

## 1. X3DH — Extended Triple Diffie-Hellman

**Problem it solves.** Alice wants to send Bob an encrypted message *right now*, but Bob is offline. Classical DH needs both parties online at the same time. X3DH lets Bob pre-publish enough material to a directory that Alice can derive a shared secret unilaterally and start sending.

**The pieces Bob publishes (his "prekey bundle")**

| Key | Lifetime | Purpose |
|---|---|---|
| Identity Key `IK_B` | Permanent | Long-term identity. Verified out-of-band ideally (QR scan, etc.). |
| Signed Prekey `SPK_B` + signature with `IK_B` | Weeks-ish, rotated | Medium-term, signed by IK so anyone can check it really belongs to Bob. |
| One-time prekeys `OPK_B^i` (a stash) | Single-use | Burned after one use. Server hands one out per incoming initial message. New ones uploaded as the stash drains. |

**What Alice does**
1. Fetch Bob's bundle, verify the signature on `SPK_B`.
2. Generate her own ephemeral key `EK_A`.
3. Run **four** Diffie-Hellman computations and concatenate the outputs:
   - `DH1 = DH(IK_A, SPK_B)` — your identity ↔ his medium-term key
   - `DH2 = DH(EK_A, IK_B)` — your ephemeral ↔ his identity
   - `DH3 = DH(EK_A, SPK_B)` — your ephemeral ↔ his medium-term
   - `DH4 = DH(EK_A, OPK_B^i)` — your ephemeral ↔ his one-time (skipped if no OPK left)
4. `SK = KDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4)` is the shared session key.
5. Encrypt initial message under `SK` (technically under a key derived from `SK`), send along with `IK_A`, `EK_A`, and which `OPK^i` was used.
6. Delete `EK_A`'s private key.

**What Bob does** when he comes online: looks up the matching private OPK, runs the four DHs from his side, gets the same `SK`, decrypts. He then deletes the used OPK private key — so even if his device is compromised later, the OPK is already gone and that initial message can't be re-derived.

**Why each DH is there.** The combination gives you mutual implicit authentication:
- `DH1` proves Alice is talking to whoever holds `IK_B`.
- `DH2` proves Bob is talking to whoever holds `IK_A`.
- `DH3` and `DH4` mix in ephemerals → forward secrecy: erasing them later means the past session can never be re-derived.

**What X3DH gives you**
- Asynchronous handshake.
- Forward secrecy (because of the ephemerals).
- Mutual authentication (assuming you trust `IK`).
- Some deniability (no signature on the actual message — only on `SPK`).

**What X3DH does *not* do.** It only bootstraps the session. After the first message, you need an ongoing protocol — that's Double Ratchet.

**Practical gotchas.** OPK exhaustion (server falls back to no-OPK mode, which weakens forward secrecy on the very first message). Need a robust prekey rotation policy. TOFU (trust-on-first-use) is the default; out-of-band identity verification is what makes it strong.

---

## 2. Double Ratchet (DR)

**Problem it solves.** Given a starting shared secret (from X3DH), encrypt an unbounded stream of messages with both **forward secrecy** *and* **post-compromise security**, even when messages can be reordered or lost.

**The two ratchets, intuitively**

```
       ┌───────────────────────────────────────────────────────┐
       │                  ROOT KEY                              │
       │   (advances each time the conversation reverses)       │
       └────────────┬──────────────────────────────────────────┘
                    │ DH ratchet step
        ┌───────────┴────────────┐
        ▼                        ▼
  Sending chain            Receiving chain
   (KDF chain)              (KDF chain)
   msg_key_1                msg_key_1
   msg_key_2                msg_key_2
   msg_key_3                msg_key_3
       …                        …
```

- **Symmetric (chain) ratchet.** Within one "direction" of the conversation, you derive the key for message N from the key for message N−1 by a KDF. Each message gets a unique key; the key for message N can't be recovered from N+1 (KDF is one-way). This is what gives you per-message forward secrecy.
- **DH ratchet.** Each message header carries the sender's current DH public key. The first time the recipient sees a *new* DH public key, both parties perform a DH step, mix the result into the root key, and start a fresh chain. This is what gives you post-compromise security: once a DH step happens, an attacker who held the previous state can no longer decrypt new messages.

**One round in slow motion** (Alice sends a few, Bob replies):

1. Alice's "sending chain" derives `msg_key_1`, `msg_key_2`, `msg_key_3` and encrypts three messages. Each header includes her current DH public key `A1`.
2. Bob receives them. He's never seen `A1` before, so he runs `DH(b, A1)`, mixes into root, derives a new "receiving chain" → decrypts all three.
3. Bob wants to reply. He generates a new DH key `B2`, runs `DH(B2, A1)`, mixes into root, derives a new "sending chain", encrypts his message with `B2` in the header.
4. Alice receives Bob's message, sees the new `B2`, runs the DH from her side, derives the same root, decrypts. From here she'll generate `A2` for her next reply, and the cycle repeats.

**Out-of-order delivery.** Real-world messages arrive late or out of order. DR handles this by *keeping a bounded buffer of skipped message keys*. If Alice sent messages 5, 6, 7 and message 5 arrived last, Bob derived and stored `msg_key_5` when he was at chain position 4, set it aside, and uses it when 5 finally shows up.

**What DR gives you**
- Per-message forward secrecy.
- Post-compromise security (every direction reversal triggers a DH step).
- Out-of-order tolerance via the skipped-keys buffer.

**Limitations**
- Strictly 1:1. Doing N members pairwise = N² sessions, doesn't scale.
- Skipped-keys buffer must be bounded (else trivial DoS by sending a header with a large gap).
- No deniability for *replies* to your initial X3DH message (the DH ratchet binds you to your identity).
- Multi-device = separate DR sessions per device pair — bookkeeping.

---

## 3. Sender Keys

**Problem it solves.** Doing Double Ratchet pairwise for a group of size N means sending N ciphertexts per message. Bandwidth and CPU don't scale.

**Idea.** Each sender maintains *one* symmetric chain ("sender chain") that all group members can decrypt. They distribute the sender chain to every group member *once* (over the existing 1:1 Double Ratchet sessions, which are the secure pairwise channels). Then every group message is encrypted **once** with a key derived from the sender's chain.

**The pieces (per sender, per group)**
- **Sender chain key** — starts random, advances by KDF after each message.
- **Sender message key** — derived per-message from the chain key.
- **Sender signing key pair** — used to sign each message. Necessary because all group members hold the same symmetric key, so the symmetric key alone proves nothing about which member sent the message.

**Join flow.** When Alice joins the group:
- For every existing member M, the senders take their current sender chain key + signing public key and send it to M *over the 1:1 DR session with M*.
- M now has: their own sender chain (for sending) + every other sender's chain (for receiving).

**Send flow.**
1. Derive next `msg_key` from sender chain key.
2. Advance sender chain key.
3. Encrypt with AEAD using `msg_key`, sign with sender signing key.
4. Broadcast the single ciphertext + signature to all group members.

**Remove flow** *(the painful part).*
- A removed member must lose access to future messages.
- Every remaining sender generates a *fresh* sender chain + signing key pair.
- Each sender re-distributes their fresh keys to every remaining member via the 1:1 DR sessions.
- Cost: O(N²) ciphertexts for N remaining senders × N−1 recipients.

**What Sender Keys gives you**
- Cheap sending: one ciphertext per message, regardless of group size.
- Forward secrecy on the symmetric chain (per-message keys discarded).

**What it does *not* give you (well)**
- **No post-compromise security inside the group flow.** The sender chain advances by KDF only — no DH steps within the group. If an attacker steals the chain key once, they can decrypt every future message that sender sends *until the sender manually rotates*. There's no automatic recovery.
- **Expensive removes.** You're paying for security at remove time.
- **Per-sender state proliferation.** Every active sender has their own chain that every member must store.

This is the design Signal/WhatsApp use for groups today. It works in practice but the security gap vs 1:1 DR is the main reason MLS was standardised.

---

## 4. MLS — Messaging Layer Security (RFC 9420)

**Problem it solves.** Provide *one* protocol that covers groups (any size from 2 upwards) with **forward secrecy AND post-compromise security AND O(log N) group operations**, in a vendor-neutral, federation-friendly way.

**Core idea: TreeKEM.** The group is a balanced binary tree.
- **Leaves** = members (or devices, if you treat each device as a leaf).
- **Internal nodes** = HPKE key pairs derived from their two children.
- **Root** = the group secret from which message keys are derived.

```
                      root_key (derives epoch secrets)
                       /           \
                   node_3         node_4
                  /     \         /    \
             leaf_A  leaf_B   leaf_C  leaf_D
              (Alice) (Bob)   (Carol)  (Dave)
```

**What every member knows.** Each member holds the private keys for the nodes on the path from their leaf up to the root — plus the public keys for every node they don't own. Crucially: nobody but Alice has all four leaves' private keys. The structure means each operation only needs to update O(log N) nodes.

**KeyPackages.** Like X3DH prekey bundles. Each user (or device) publishes a `KeyPackage` containing:
- Identity credential (e.g. signed by your IdP — this is where your existing auth integrates).
- HPKE init key (used to add this user to a group).
- Lifetime, signature, extensions.

When you want to add Alice to a group, the group fetches her KeyPackage from her IdP and uses its init key to encrypt the path-secrets she needs.

**Operations.** Group changes are proposed and committed:
- **Add(member)** — insert at a free leaf (or grow the tree), update path keys.
- **Remove(member)** — blank out their leaf, update path keys.
- **Update(self)** — rotate own leaf key + path keys (used for periodic post-compromise refresh).
- **Commit** — applies a batch of proposals atomically. Every commit advances the group to a new "epoch" with a fresh epoch secret. Each member processes the commit and derives the same new state.

Each operation rotates every key on the affected path → O(log N) ciphertexts to distribute the new path secrets, encrypted under the public keys at the appropriate sub-trees.

**Welcome.** When a new member is added, they receive a `Welcome` message that gives them the current group state (tree, epoch, secrets needed to derive their part of the tree).

**Per-message encryption.** Within an epoch, messages use a sub-ratchet:
- A sender ratchet derives per-message keys (similar to Sender Keys' chain), but the ratchet seed is fresh every epoch — so removing a member or any commit triggers a global re-rooting.
- Application messages carry their generation counter for in-epoch ordering.

**Protocol roles.**
- **Authentication Service (AS).** Vouches for identity-credential bindings. Your existing IdP's OIDC/WebFinger plays this role — it already says "this `actor_uri` is this person".
- **Delivery Service (DS).** Relays handshakes (commits, welcomes) and application messages, maintaining ordering. Your IdP's messaging backbone is essentially already a DS — it just needs to relay opaque ciphertext + protocol headers and enforce ordering of commits.
- The DS sees who's in the group, when commits happen, and message ordering — but never sees plaintext.

**What MLS gives you**
- Forward secrecy (every commit advances epoch keys, every message advances the in-epoch ratchet).
- Post-compromise security (any member doing Update, or any add/remove, triggers a rekey on their path → an attacker who held that state recovers no future content).
- O(log N) cost per group operation.
- Federation-friendly: the spec separates protocol from delivery service; each IdP can be a DS for its members.
- Standardised: RFC 9420, multiple interoperable implementations.

**Trade-offs**
- More complex than Signal's stack — both to implement and to reason about.
- Group state is non-trivial to keep in sync. Concurrent commits require explicit conflict resolution (the spec defines it; you have to implement it).
- Library landscape is younger but maturing fast (`openmls` is the leading Rust impl and tracks the RFC closely).

---

## How they compose in real systems

It's worth seeing how these snap together because they're not alternatives in isolation:

| Stack | Handshake | 1:1 ongoing | Group ongoing | Used by |
|---|---|---|---|---|
| **Signal Protocol** | X3DH | Double Ratchet | Sender Keys (over DR sessions) | Signal, WhatsApp, Wire (formerly), … |
| **MLS** | KeyPackage exchange (analogous role to X3DH) | TreeKEM (group of 2) | TreeKEM | Wire (now), Cisco Webex, RingCentral, others moving over |

So when people say "I want to use MLS", they typically mean replacing the entire Signal stack with one MLS-based stack. When people say "I want to use the Signal Protocol", they mean X3DH + DR + Sender Keys together.

---

## A note on the security properties to prioritise

When you sit down to compare them, ranking the security properties for a federated chat:

1. **Forward secrecy** — table stakes, all of these have it.
2. **Post-compromise security** — DR has it for 1:1, MLS has it for groups, Sender Keys does *not* really have it for groups. This is the single biggest reason new systems lean MLS.
3. **Standardisation / interop** — MLS is an RFC; Signal stack is a published spec but not an RFC, and implementations diverge.
4. **Scalability** — MLS is O(log N); Sender Keys removal is O(N²). Matters once groups exceed ~50.
5. **Deniability** — both stacks offer some; MLS's commit signatures arguably weaken it slightly. Mostly relevant for journalists/whistleblowers — probably not the top concern for a Discord-like app.
