# bucket_exposure_check

A scope-driven **cloud-storage misconfiguration detector** for *authorized*
bug-bounty recon, covering AWS S3, Azure Blob, and GCP Cloud Storage.

It exists to answer one question accurately: **is a named bucket/container
publicly listable, or is a storage-backed subdomain takeover-able?** It proves
exposure and stops. It is not an exfiltration, control-bypass, or evasion tool —
by design, because those behaviors get bug-bounty reports rejected and
researchers removed from programs.

---

## Authorized use only

This tool is for testing assets that a bug-bounty/VDP program's brief explicitly
lists **in scope**, or that you otherwise own or are contractually authorized to
test. Authorization on platforms like Bugcrowd or HackerOne is **per program** —
it does not carry from one engagement to another, and it never extends to
untargeted scanning of arbitrary organizations.

Because of that, the tool will not run without an authorization step:

- **Scripted:** you must pass `--authorized` alongside `--scope`.
- **Interactive:** you must type `in scope` to confirm your targets are covered
  by the program's brief.

You are responsible for confirming scope before every run. Accessing storage you
are not authorized to test may violate the CFAA (US), the Computer Misuse Act
(UK), and equivalents elsewhere — regardless of whether the bucket is
misconfigured.

---

## What it does (and deliberately does not)

**Does**

- Generates bucket/container name candidates from *your* in-scope tokens only —
  thoroughly: both organization name and domain, multi-word org names,
  acronyms, all separators (`-`, `_`, `.`, none), env/year/numeric suffixes, and
  cross-combinations, emitted in likelihood order so the cap keeps the best.
- Optional Certificate-Transparency expansion (crt.sh) to discover in-scope
  subdomains that naming conventions miss.
- Optional DNS/CNAME resolution to flag **subdomain-takeover candidates**
  (a dangling CNAME pointing at an unclaimed storage endpoint).
- Checks existence + anonymous listability across S3, Azure Blob, GCP Storage.
- Follows S3 region redirects, runs a confirm pass on every public hit, and
  assigns a confidence rating — to minimize false positives.
- Polite exponential backoff honoring HTTP `429` / `Retry-After`.
- Writes report-ready `findings.md` and `findings.json`.

**Does not (on purpose)**

- Download object *contents* — it records object *keys* as evidence, nothing more.
- Touch private buckets beyond noting they exist. A `403 / AccessDenied` means
  the control works; there is no vulnerability to "prove," and bypassing it is
  unauthorized access.
- Persist, brute-force credentials, or evade WAF/rate limits. Backoff is for
  reliability and good citizenship, not stealth.

The valid proof-of-concept for a storage finding is minimal: a `ListBucketResult`
to an anonymous request, a planted `flag.txt`, or a dangling-CNAME response —
capture it, report it, stop.

---

## Requirements

- Python 3.8+ (standard library only — no `pip install` needed).
- Outbound network access. `--ct` contacts `crt.sh`; `--dns` uses your system
  resolver. Both are standard passive-recon sources.

---

## Usage

### Interactive (prompts for program, targets, and the in-scope confirmation)

```bash
python3 bucket_exposure_check.py
```

### Scripted

Create a scope file with authorized base tokens/domains, one per line:

```
# scope.txt — must match the program's in-scope assets
tmobile
t-mobile
tmobile.com
```

Run:

```bash
python3 bucket_exposure_check.py \
    --scope scope.txt --authorized \
    --program "T-Mobile" \
    --providers aws,azure,gcp \
    --ct --dns \
    --out findings
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--scope FILE` | — | Authorized tokens/domains, one per line. Omit for interactive mode. |
| `--authorized` | off | **Required with `--scope`.** Affirms the tokens are in the program's brief. |
| `--program NAME` | `unspecified` | Program name, used in the report header. |
| `--providers` | `aws,azure,gcp` | Comma list of providers to check. |
| `--ct` | off | Expand scope via Certificate Transparency (in-scope domains only). |
| `--dns` | off | Resolve discovered subdomains; flag storage-CNAME takeover candidates. |
| `--max-candidates N` | `2000` | Cap on generated bucket names (likelihood-ordered). Raise for more coverage. |
| `--rate-delay S` | `0.3` | Seconds slept before each request (politeness). |
| `--workers N` | `8` | Concurrent requests. Keep modest for accuracy and courtesy. |
| `--out BASE` | `findings` | Output basename; writes `BASE.md` and `BASE.json`. |

---

## Output

- **`findings.md`** — human-readable report split into: publicly listable
  buckets (your findings), subdomain-takeover candidates, and existing-but-locked
  buckets (recon evidence only).
- **`findings.json`** — structured results for tooling or to feed a
  submission template.

Example console output:

```
[PUBLIC]   aws-s3       acme-dev-assets  <-- listable, capture evidence
[TAKEOVER] cdn.acme.com  <-- dangling storage CNAME
[exists]   aws-s3       acme-backups  (private (AccessDenied))
```

---

## Recommended workflow

1. Open the target program on Bugcrowd/HackerOne and read its scope and rules.
2. Put only the in-scope tokens/domains into `scope.txt`.
3. Run with `--ct --dns` for full discovery; keep `--workers` modest.
4. For each `[PUBLIC]` or `[TAKEOVER]` result, capture the evidence the report
   already recorded — and **stop there**. Do not download real data or claim
   the subdomain.
5. File the report against the program's severity rating, with reproduction
   steps and remediation (S3 Block Public Access; Azure RBAC + disable anonymous
   access; GCP uniform bucket-level access; server-side encryption; access
   logging).

---

## Remediation guidance for target owners

- **AWS S3:** enable Block Public Access at account + bucket level; review bucket
  policies and ACLs; enable default encryption and access logging.
- **Azure Blob:** disable anonymous public access on storage accounts and
  containers; enforce RBAC / SAS with least privilege; enable logging.
- **GCP Cloud Storage:** enable uniform bucket-level access; remove
  `allUsers` / `allAuthenticatedUsers` bindings; enable audit logging.

---

## License / disclaimer

Provided as-is for lawful, authorized security testing and education. The user
is solely responsible for ensuring they have permission to test any target.
