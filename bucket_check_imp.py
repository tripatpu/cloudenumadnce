#!/usr/bin/env python3
"""
bucket_exposure_check.py  (v2 — advanced discovery, detection-only)
===================================================================
Scope-driven cloud-storage misconfiguration DETECTOR for authorized bug-bounty
recon across AWS S3, Azure Blob, and GCP Cloud Storage.

WHAT MAKES IT "ADVANCED" — and what it deliberately is NOT
  Advanced here = better DISCOVERY + fewer FALSE POSITIVES + report-ready
  evidence. That's what actually wins bounties.
    * Certificate-Transparency subdomain expansion (crt.sh) for in-scope domains.
    * DNS/CNAME resolution to catch storage endpoints that bypass naming rules.
    * Subdomain-takeover CANDIDATE detection (dangling CNAME -> unclaimed bucket)
      — flagged only, never claimed.
    * Region-redirect following + confirm passes + confidence scoring.
    * Polite exponential backoff honoring HTTP 429 / Retry-After.

  It is NOT, on purpose:
    * an exfiltrator — it never downloads object contents;
    * a control-bypass — a 403/AccessDenied is recorded as existence only;
    * an evasion tool — backoff is for reliability/good-citizenship, not stealth.
  Proving a bucket is publicly listable (or a takeover is possible) IS the
  finding. Capture the evidence, report it, stop.

AUTHORIZATION
  Every run requires either --authorized (with --scope) or the interactive
  "in scope" confirmation. Targets must be assets the program's brief lists in
  scope. Untargeted scanning is not authorized on any platform.

USAGE
  Interactive:   python3 bucket_exposure_check.py
  Scripted:      python3 bucket_exposure_check.py --scope scope.txt --authorized \
                     --program "T-Mobile" --ct --dns --out findings

Standard library only (3.8+). --ct and --dns make outbound requests to crt.sh
and your resolver respectively; both are standard passive-recon sources.
"""

import argparse
import concurrent.futures
import datetime
import json
import re
import socket
import sys
import time
import urllib.request
import urllib.error

USER_AGENT = "bugbounty-scope-recon/2.0 (authorized-testing-only)"


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")

# Affix WORDS (no separators baked in — separators are applied combinatorially).
PREFIX_WORDS = ["dev", "prod", "test", "staging", "stage", "qa", "uat",
                "sandbox", "demo", "shared", "internal", "int", "external",
                "public", "private", "corp", "confidential", "archive",
                "backup", "backups", "bak", "logs", "log", "assets", "asset",
                "media", "img", "images", "uploads", "upload", "downloads",
                "download", "cdn", "static", "files", "data", "db", "www",
                "web", "app", "api", "s3", "storage", "cloud"]
SUFFIX_WORDS = ["data", "files", "file", "storage", "store", "cloud",
                "resources", "resource", "private", "public", "restricted",
                "temp", "tmp", "bak", "backup", "backups", "old", "new",
                "assets", "asset", "logs", "log", "media", "static", "prod",
                "dev", "test", "stage", "staging", "qa", "uat", "s3", "bucket",
                "blob", "container", "archive", "internal", "shared", "images",
                "uploads", "downloads", "cdn", "db", "dump", "dumps", "hr",
                "finance", "pii", "reports", "config", "configs"]
SEPARATORS = ["-", "_", ".", ""]
# Environment/number suffixes appended after an optional separator.
NUM_SUFFIXES = ["1", "2", "01", "02", "0", "prod1", "dev1"]

STORAGE_CNAME_MARKERS = ("s3.amazonaws.com", "s3-website", ".s3.",
                         "blob.core.windows.net", "storage.googleapis.com",
                         "web.core.windows.net")


# --------------------------------------------------------------------------- #
# HTTP with polite backoff (reliability + good citizenship, not evasion)
# --------------------------------------------------------------------------- #
def http_get(url, timeout=8, max_tries=3):
    delay = 1.0
    for attempt in range(max_tries):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                ra = e.headers.get("Retry-After")
                wait = float(ra) if (ra and ra.isdigit()) else delay
                time.sleep(min(wait, 15))
                delay *= 2
                continue
            body = ""
            try:
                body = e.read(65536).decode("utf-8", "replace")
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, ""
    return None, ""


def sample_keys(xml_body, cap=10):
    """Object KEYS only, as report evidence — never contents."""
    return re.findall(r"<Key>([^<]+)</Key>", xml_body)[:cap]


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def normalize_token(token):
    """Turn one supplied org name / domain into every plausible base label.
    Handles multi-word org names, domains, and acronyms."""
    token = token.strip().lower()
    if not token:
        return []
    bare = re.sub(r"\.[a-z]{2,}$", "", token)          # drop TLD if a domain
    words = re.split(r"[\s._\-]+", bare)                # split multi-word names
    words = [w for w in words if w]
    variants = set()
    if words:
        # Joined forms with each separator, e.g. acme-corp / acme_corp / acmecorp
        for sep in SEPARATORS:
            variants.add(sep.join(words))
        # Acronym from initials (e.g. "amazon web services" -> "aws")
        if len(words) > 1:
            variants.add("".join(w[0] for w in words))
        # Each individual significant word on its own
        for w in words:
            if len(w) >= 3:
                variants.add(w)
    variants.add(bare.replace(".", "-"))
    variants.add(bare.replace(".", ""))
    return [v for v in variants if v and re.fullmatch(r"[a-z0-9\-]{1,50}", v)]


def ct_subdomains(domain, limit=200):
    """Passive subdomain discovery via Certificate Transparency (crt.sh).
    Only called for in-scope domains you supplied."""
    out = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, body = http_get(url, timeout=20)
    if status != 200 or not body:
        return out
    try:
        for row in json.loads(body):
            for nv in str(row.get("name_value", "")).splitlines():
                nv = nv.strip().lower().lstrip("*.")
                if nv.endswith(domain) and "@" not in nv:
                    out.add(nv)
    except Exception:
        pass
    return set(list(out)[:limit])


def resolve_cname(host):
    """Best-effort canonical-name resolution (stdlib). Returns (canonical,
    aliases) — enough to spot storage endpoints and dangling records."""
    try:
        canonical, aliases, _ = socket.gethostbyname_ex(host)
        return canonical.lower(), [a.lower() for a in aliases]
    except socket.gaierror:
        return None, []          # NXDOMAIN / unresolvable -> takeover signal
    except Exception:
        return "", []


def _valid_bucket(name):
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9]", name))


def build_candidates(scope_tokens, max_candidates, years=None):
    """Very thorough, but ordered by likelihood so the cap keeps the best names.
    Tiers (highest-probability first):
      0  base itself + base+base cross-combinations
      1  prefix<sep>base   and   base<sep>suffix
      2  prefix<sep>base<sep>suffix
      3  base<sep>{year|num}
    Only ever combines the tokens YOU supplied with generic affix words.
    """
    bases = []
    for t in scope_tokens:
        bases.extend(normalize_token(t))
    bases = list(dict.fromkeys(bases))

    # Cross-combine distinct bases (e.g. org + product): acme + payments
    combos = []
    for i, a in enumerate(bases):
        for b in bases[i + 1:]:
            for sep in SEPARATORS:
                combos.append(f"{a}{sep}{b}")
    core = list(dict.fromkeys(bases + combos))

    years = years or []
    seen, out = set(), []

    def add(name):
        if _valid_bucket(name) and name not in seen:
            seen.add(name)
            out.append(name)
        return len(out) < max_candidates

    # Tier 0 — bare cores
    for base in core:
        if not add(base):
            return out
    # Tier 1 — single affix
    for base in core:
        for sep in SEPARATORS:
            for w in PREFIX_WORDS:
                if not add(f"{w}{sep}{base}"):
                    return out
            for w in SUFFIX_WORDS:
                if not add(f"{base}{sep}{w}"):
                    return out
    # Tier 3 — year / numeric (cheap, high value)
    for base in core:
        for sep in SEPARATORS:
            for y in list(years) + NUM_SUFFIXES:
                if not add(f"{base}{sep}{y}"):
                    return out
    # Tier 2 — double affix (largest space, last so cap trims it)
    for base in core:
        for sep in SEPARATORS:
            for pre in PREFIX_WORDS:
                for suf in SUFFIX_WORDS:
                    if not add(f"{pre}{sep}{base}{sep}{suf}"):
                        return out
    return out


# --------------------------------------------------------------------------- #
# Provider checks — existence + anonymous listability ONLY, with confidence
# --------------------------------------------------------------------------- #
def _s3_region_endpoint(name, body):
    m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body)
    if m:
        return f"http://{m.group(1)}/"
    m = re.search(r"<Region>([^<]+)</Region>", body)
    if m:
        return f"http://{name}.s3.{m.group(1)}.amazonaws.com/"
    return None


def check_s3(name, confirm=True):
    url = f"http://{name}.s3.amazonaws.com/"
    status, body = http_get(url)
    if status in (301, 307, 400) and any(k in body for k in
            ("Redirect", "Region", "AuthorizationHeaderMalformed")):
        ep = _s3_region_endpoint(name, body)
        if ep:
            url = ep
            status, body = http_get(ep)
    r = {"target": name, "provider": "aws-s3", "url": url, "http_status": status,
         "checked_at": _now_iso()}
    if status == 200 and "<ListBucketResult" in body:
        if confirm:
            s2, b2 = http_get(url)
            if not (s2 == 200 and "<ListBucketResult" in b2):
                return {**r, "exists": "yes", "listable": "unclear (unstable)",
                        "confidence": "low"}
            body = b2
        return {**r, "exists": "yes", "listable": "PUBLIC", "confidence": "high",
                "evidence": "anonymous ListBucketResult (confirmed)",
                "sample_keys": sample_keys(body)}
    if status == 403 or "AccessDenied" in body:
        return {**r, "exists": "yes", "listable": "private (AccessDenied)",
                "confidence": "high"}
    if status == 404 or "NoSuchBucket" in body:
        return {**r, "exists": "no", "listable": "n/a", "confidence": "high"}
    if status is None:
        return {**r, "exists": "unknown", "listable": "unknown",
                "confidence": "low"}
    return {**r, "exists": "maybe", "listable": "unclear", "confidence": "low"}


def check_azure(name, confirm=True):
    account = re.sub(r"[^a-z0-9]", "", name)[:24]
    if len(account) < 3:
        return None
    url = f"https://{account}.blob.core.windows.net/?comp=list"
    status, body = http_get(url)
    r = {"target": account, "provider": "azure-blob", "url": url,
         "http_status": status,
         "checked_at": _now_iso()}
    if status == 200 and "EnumerationResults" in body:
        return {**r, "exists": "yes", "listable": "PUBLIC", "confidence": "high",
                "evidence": "anonymous container enumeration succeeded"}
    if status in (400, 403, 409):
        return {**r, "exists": "yes", "listable": "private/blocked",
                "confidence": "medium"}
    if status == 404:
        return {**r, "exists": "no", "listable": "n/a", "confidence": "high"}
    return {**r, "exists": "maybe", "listable": "unclear", "confidence": "low"}


def check_gcp(name, confirm=True):
    url = f"https://storage.googleapis.com/{name}/"
    status, body = http_get(url)
    r = {"target": name, "provider": "gcp-storage", "url": url,
         "http_status": status,
         "checked_at": _now_iso()}
    if status == 200 and "<ListBucketResult" in body:
        return {**r, "exists": "yes", "listable": "PUBLIC", "confidence": "high",
                "evidence": "anonymous ListBucketResult",
                "sample_keys": sample_keys(body)}
    if status == 403 or "AccessDenied" in body:
        return {**r, "exists": "yes", "listable": "private (AccessDenied)",
                "confidence": "high"}
    if status in (404,) or "NoSuchBucket" in body:
        return {**r, "exists": "no", "listable": "n/a", "confidence": "high"}
    return {**r, "exists": "maybe", "listable": "unclear", "confidence": "low"}


def check_takeover(host):
    """Flag a subdomain whose CNAME points at storage but resolves to an
    unclaimed/missing bucket — a subdomain-takeover CANDIDATE. Flag only."""
    canonical, aliases = resolve_cname(host)
    chain = " ".join([canonical or ""] + aliases)
    if not any(m in chain for m in STORAGE_CNAME_MARKERS):
        return None
    r = {"target": host, "provider": "dns-cname", "cname_chain": chain.strip(),
         "checked_at": _now_iso()}
    # If the storage host errors as missing, it's a takeover candidate.
    probe = f"http://{host}/"
    status, body = http_get(probe)
    if status in (404,) or "NoSuchBucket" in body or "The specified bucket" in body:
        return {**r, "finding": "SUBDOMAIN-TAKEOVER-CANDIDATE", "confidence":
                "medium", "evidence": f"CNAME -> storage, HTTP {status} "
                f"missing-bucket response", "http_status": status}
    return {**r, "finding": "storage-cname (claimed)", "confidence": "info",
            "http_status": status}


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run(candidates, subdomains, providers, rate_delay, workers):
    findings = []
    tasks = []
    for name in candidates:
        if "aws" in providers:
            tasks.append(("s3", name))
        if "azure" in providers:
            tasks.append(("azure", name))
        if "gcp" in providers:
            tasks.append(("gcp", name))
    for host in subdomains:
        tasks.append(("takeover", host))

    fn = {"s3": check_s3, "azure": check_azure, "gcp": check_gcp,
          "takeover": check_takeover}

    def do(task):
        kind, val = task
        time.sleep(rate_delay)
        return fn[kind](val)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(do, tasks):
            if not res:
                continue
            findings.append(res)
            if res.get("listable") == "PUBLIC":
                print(f"[PUBLIC]   {res['provider']:12} {res['target']}  "
                      f"<-- listable, capture evidence")
            elif res.get("finding") == "SUBDOMAIN-TAKEOVER-CANDIDATE":
                print(f"[TAKEOVER] {res['target']}  <-- dangling storage CNAME")
            elif res.get("exists") == "yes":
                print(f"[exists]   {res['provider']:12} {res['target']}  "
                      f"({res.get('listable','')})")
    return findings


def write_report(findings, program, out_base):
    with open(out_base + ".json", "w") as f:
        json.dump({"program": program,
                   "generated_at": _now_iso(),
                   "findings": findings}, f, indent=2)

    public = [f for f in findings if f.get("listable") == "PUBLIC"]
    takeover = [f for f in findings
                if f.get("finding") == "SUBDOMAIN-TAKEOVER-CANDIDATE"]
    exists = [f for f in findings if f.get("exists") == "yes"
              and f.get("listable") != "PUBLIC"]

    L = [f"# Cloud storage exposure recon — {program}",
         f"_Generated {_now_iso()}. Authorized testing only._\n",
         f"**Checks:** {len(findings)}  |  **Publicly listable:** {len(public)} "
         f" |  **Takeover candidates:** {len(takeover)}  |  "
         f"**Existing (locked):** {len(exists)}\n"]
    if public:
        L.append("## Publicly listable — report these (high confidence)\n")
        for f in public:
            L.append(f"### `{f['target']}` ({f['provider']})")
            L.append(f"- URL: {f['url']}")
            L.append(f"- HTTP {f['http_status']} — {f.get('evidence','')}")
            if f.get("sample_keys"):
                L.append(f"- Sample keys (evidence, no contents retrieved): "
                         f"{f['sample_keys']}")
            L.append(f"- Observed: {f['checked_at']}\n")
    if takeover:
        L.append("## Subdomain-takeover candidates (verify, then report)\n")
        for f in takeover:
            L.append(f"- `{f['target']}` — {f.get('evidence','')}")
            L.append(f"  - CNAME chain: `{f.get('cname_chain','')}`")
        L.append("")
    if exists:
        L.append("## Exist but not anonymously listable (recon evidence)\n")
        for f in exists:
            L.append(f"- `{f['target']}` ({f['provider']}) — {f.get('listable')}")
    if not (public or takeover):
        L.append("_No publicly listable buckets or takeover candidates found._")
    with open(out_base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")


def interactive_scope():
    print("=== S3/Azure/GCP exposure detector (authorized recon) ===")
    program = input("Bugcrowd program name: ").strip() or "unspecified"
    print("Org name / domains to enumerate (must be in the program's scope),")
    print("one per line, blank line to finish:")
    tokens = []
    while True:
        line = input("  > ").strip()
        if not line:
            break
        tokens.append(line)
    if not tokens:
        sys.exit("No targets entered.")
    print(f"\nProgram '{program}', {len(tokens)} target(s):")
    for t in tokens:
        print(f"   - {t}")
    print("\nConfirm every target above is IN SCOPE for this program's brief")
    print("and you are authorized to test it.")
    if input("Type 'in scope' to proceed: ").strip().lower() != "in scope":
        sys.exit("Not confirmed as in scope. Aborting.")
    return program, tokens


def main():
    p = argparse.ArgumentParser(description="Advanced scope-driven S3/Azure/GCP "
                                "exposure detector (authorized recon only).")
    p.add_argument("--scope", help="Authorized tokens/domains file, one per "
                   "line. Omit for interactive mode.")
    p.add_argument("--authorized", action="store_true",
                   help="Required with --scope; affirms in-scope authorization.")
    p.add_argument("--program", default="unspecified")
    p.add_argument("--providers", default="aws,azure,gcp",
                   help="Comma list of aws,azure,gcp (default all).")
    p.add_argument("--ct", action="store_true",
                   help="Expand scope via Certificate Transparency (crt.sh).")
    p.add_argument("--dns", action="store_true",
                   help="Resolve discovered subdomains, flag storage-CNAME "
                        "takeover candidates.")
    p.add_argument("--max-candidates", type=int, default=2000,
                   help="Cap on generated names (default 2000 for thorough "
                        "coverage; names are ordered by likelihood).")
    p.add_argument("--rate-delay", type=float, default=0.3)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--out", default="findings")
    args = p.parse_args()

    program = args.program
    if args.scope:
        if not args.authorized:
            sys.exit("Refusing to run: pass --authorized to affirm --scope "
                     "tokens are in the program's brief. Untargeted scanning "
                     "is not authorized.")
        try:
            with open(args.scope) as f:
                scope_tokens = [ln.strip() for ln in f
                                if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            sys.exit(f"Cannot read scope file: {e}")
        if not scope_tokens:
            sys.exit("Scope file is empty.")
    else:
        program, scope_tokens = interactive_scope()

    print(f"[i] Program: {program}")
    print(f"[i] Authorized tokens: {scope_tokens}")

    # Certificate-Transparency expansion (in-scope domains only).
    subdomains = set()
    domains = [t.strip().lower() for t in scope_tokens if "." in t]
    if args.ct and domains:
        for d in domains:
            found = ct_subdomains(re.sub(r"^\*?\.?", "", d))
            print(f"[ct] {d}: +{len(found)} subdomains from crt.sh")
            subdomains |= found
    # Only resolve/takeover-check subdomains if --dns is set.
    takeover_hosts = sorted(subdomains) if args.dns else []

    this_year = datetime.datetime.now(datetime.timezone.utc).year
    years = [str(y) for y in range(this_year - 3, this_year + 1)]
    candidates = build_candidates(scope_tokens, args.max_candidates, years)
    # Fold CT subdomain labels into bucket-name guessing too.
    for s in list(subdomains)[:200]:
        label = s.split(".")[0]
        if re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", label):
            candidates.append(label)
    candidates = list(dict.fromkeys(candidates))[:args.max_candidates + 200]
    print(f"[i] {len(candidates)} bucket candidates, "
          f"{len(takeover_hosts)} subdomains for takeover check.")

    providers = [x.strip() for x in args.providers.split(",")]
    findings = run(candidates, takeover_hosts, providers,
                   args.rate_delay, args.workers)
    write_report(findings, program, args.out)

    pub = sum(1 for f in findings if f.get("listable") == "PUBLIC")
    tko = sum(1 for f in findings
              if f.get("finding") == "SUBDOMAIN-TAKEOVER-CANDIDATE")
    print(f"\n[done] {len(findings)} checks | {pub} public | {tko} takeover "
          f"candidates. Report: {args.out}.md / {args.out}.json")
    if pub or tko:
        print("[next] Capture the ListBucketResult / dangling-CNAME evidence, "
              "then STOP. Do not download real data or claim the subdomain. "
              "File against the program's severity chart.")


if __name__ == "__main__":
    main()
