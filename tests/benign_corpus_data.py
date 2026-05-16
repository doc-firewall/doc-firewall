"""G.5 — Deterministic benign-document corpus generator.

Produces >= 200 realistic, *benign* documents by parameterising a set of
real-world templates (resumes, contracts, technical docs, policies, finance,
academic, marketing, runbooks, support tickets, CSV/spreadsheet text, READMEs)
with rotating names / companies / numbers / dates.

Design constraints:
  • Fully in-tree and deterministic (fixed seed) — no network, no external
    corpora, keeps the library air-gapped.
  • Each document is unique (parameter rotation) but realistic prose.
  • No content word exceeds the ATS frequency threshold; no injection-style
    phrasing; mentions of security/RAG/ATS vocabulary are framed as
    legitimate discussion to validate precision, not recall.

`generate_corpus()` returns a list of (doc_id, category, text, metadata)
tuples. The set is stable across runs (seeded), so the SHA-256 manifest is
reproducible.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class BenignDoc:
    doc_id: str
    category: str
    text: str
    metadata: dict

    @property
    def sha256(self) -> str:
        h = hashlib.sha256()
        h.update(self.text.encode("utf-8"))
        h.update(repr(sorted(self.metadata.items())).encode("utf-8"))
        return h.hexdigest()


_FIRST = ["Maria", "James", "Aisha", "Wei", "Carlos", "Priya", "Sofia",
          "Liam", "Noah", "Yuki", "Omar", "Elena", "Daniel", "Fatima",
          "Lucas", "Hana", "Ivan", "Grace", "Mateo", "Zara"]
_LAST = ["Santos", "Okafor", "Nguyen", "Patel", "Garcia", "Kim", "Müller",
         "Rossi", "Andersson", "Haddad", "Silva", "Tanaka", "Petrov",
         "Cohen", "Dubois", "Reyes", "Novak", "Berg", "Ferraro", "Khan"]
_COMPANY = ["Dataflow Corp", "Acme Inc", "Northwind Systems", "Helio Labs",
            "Quanta Analytics", "Beacon Software", "Vertex Cloud",
            "Cobalt Security", "Meridian Health", "Atlas Logistics",
            "Solstice Bank", "Pinegrove Media", "Aurora Robotics",
            "Crestline Legal", "Foundry Manufacturing", "Brightline Energy",
            "Cedar Retail", "Lumen Education", "Tideway Insurance",
            "Granite Telecom"]
_CITY = ["Lisbon", "Toronto", "Singapore", "Berlin", "Austin", "Nairobi",
         "São Paulo", "Tokyo", "Dublin", "Amsterdam", "Seattle", "Bogotá",
         "Stockholm", "Cape Town", "Manila", "Warsaw", "Helsinki", "Lima",
         "Oslo", "Vienna"]
_LANG = ["Go", "Python", "Rust", "Java", "Scala", "TypeScript", "Kotlin",
         "C++", "Ruby", "Elixir"]
_DOMAIN = ["distributed systems", "payment processing", "data engineering",
           "observability", "identity and access", "search relevance",
           "fraud detection", "supply-chain optimisation", "billing",
           "content delivery"]


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _resume(r: random.Random, idx: int) -> BenignDoc:
    name = f"{r.choice(_FIRST)} {r.choice(_LAST)}"
    lang1, lang2 = r.sample(_LANG, 2)
    dom = r.choice(_DOMAIN)
    co1, co2 = r.sample(_COMPANY, 2)
    yrs = r.randint(3, 12)
    text = f"""
    {name} — Software Engineer

    Professional Summary
    Engineer with {yrs} years of experience building reliable {dom}
    services. Comfortable across the full delivery lifecycle from design
    through on-call ownership.

    Work Experience

    Senior Engineer — {co1} ({2026 - yrs}–present)
    Led the redesign of core {dom} components, improving throughput and
    reducing operational toil. Mentored teammates and contributed to
    internal platform documentation. Primary languages were {lang1} and
    {lang2}.

    Engineer — {co2} ({2026 - yrs - 3}–{2026 - yrs})
    Maintained batch and streaming pipelines processing several terabytes
    of event data daily. Collaborated with analysts to optimise slow
    queries and improve data quality monitoring.

    Education
    B.Sc. Computer Science — University of {r.choice(_CITY)}
    ({2026 - yrs - 5})

    Technical Skills
    Languages: {lang1}, {lang2}, SQL
    Tools: Docker, Kubernetes, Terraform, Git
    """
    return BenignDoc(f"resume_{idx:03d}", "resume", text,
                     {"author": name, "title": f"{name} Resume"})


def _contract(r: random.Random, idx: int) -> BenignDoc:
    co = r.choice(_COMPANY)
    rate = r.choice([1.0, 1.25, 1.5, 2.0])
    days = r.choice([15, 30, 45, 60])
    text = f"""
    SERVICES AGREEMENT

    This Services Agreement is entered into as of the Effective Date
    between {co} ("Provider") and the counterparty identified in the
    Order Form ("Client").

    1. SCOPE. Provider shall deliver the services described in the
    applicable Statement of Work. Changes to scope require a written
    change order signed by both parties.

    2. PAYMENT. Client agrees to pay all undisputed invoices within
    {days} days of the invoice date. Late amounts accrue interest at
    {rate}% per month.

    3. CONFIDENTIALITY. Each party shall protect the other party's
    confidential information using no less than reasonable care and
    shall not disclose it to third parties without prior written consent.

    4. TERMINATION. Either party may terminate this Agreement for
    material breach if the breach remains uncured {days} days after
    written notice.

    5. GOVERNING LAW. This Agreement is governed by the laws of the
    jurisdiction specified in the Order Form, without regard to conflict
    of law principles.
    """
    return BenignDoc(f"contract_{idx:03d}", "contract", text,
                     {"title": f"{co} Services Agreement"})


def _tech_doc(r: random.Random, idx: int) -> BenignDoc:
    lang = r.choice(_LANG)
    dom = r.choice(_DOMAIN)
    qps = r.randint(20, 200) * 1000
    p99 = r.randint(8, 60)
    text = f"""
    Building a High-Throughput {dom.title()} Pipeline in {lang}

    Modern {dom} platforms must handle high request volumes with low
    end-to-end latency. This article walks through the design of such a
    pipeline using {lang} and a streaming message broker.

    We define a schema that gives both backward and forward compatibility
    as the event structure evolves. The producer batches records and
    flushes on a configurable interval. The consumer side uses a consumer
    group with several partitions for horizontal scalability.

    Error handling uses an exponential back-off strategy with a
    dead-letter queue for messages that fail after a bounded number of
    retries. Benchmarking shows sustained throughput of around {qps}
    events per second at a P99 latency of {p99} milliseconds.

    The complete example is available in the project repository.
    Contributions and issue reports are welcome through the standard
    review process.
    """
    return BenignDoc(f"techdoc_{idx:03d}", "technical", text,
                     {"title": f"{dom.title()} Pipeline in {lang}"})


def _policy(r: random.Random, idx: int) -> BenignDoc:
    co = r.choice(_COMPANY)
    ver = f"{r.randint(1,5)}.{r.randint(0,9)}"
    hrs = r.choice([2, 4, 8, 24])
    text = f"""
    Information Security Acceptable Use Policy — Version {ver}

    Purpose: This policy defines acceptable use of {co} information
    systems and data assets. All employees, contractors, and vendors
    with access must comply.

    Scope: Applies to all computing devices, network resources, and data
    owned or managed by the organisation, including cloud-hosted systems.

    Acceptable Use: Employees may use corporate systems for legitimate
    business purposes. Incidental personal use is permitted provided it
    does not interfere with operations. Follow department guidelines
    issued by your manager.

    Prohibited Activities: Unauthorised access, circumventing access
    controls, installing unapproved software, sharing credentials, or
    transmitting confidential data over unencrypted channels.

    Incident Reporting: Any suspected security incident must be reported
    to the security team within {hrs} hours of discovery. Contact the
    security operations centre rather than investigating independently.

    Violations may result in disciplinary action up to and including
    termination and referral to authorities where appropriate.
    """
    return BenignDoc(f"policy_{idx:03d}", "policy", text,
                     {"title": f"{co} Security Policy v{ver}"})


def _finance(r: random.Random, idx: int) -> BenignDoc:
    co = r.choice(_COMPANY)
    rev = r.randint(20, 200)
    growth = round(r.uniform(5, 30), 1)
    margin = round(r.uniform(55, 75), 1)
    text = f"""
    {co} — Quarterly Financial Performance Summary

    Revenue for the quarter reached ${rev}.0 million, a year-over-year
    increase of {growth}% driven by continued customer retention and
    expansion within existing accounts. Recurring revenue remains the
    majority of total revenue.

    Gross margin was {margin}%, supported by infrastructure cost
    efficiencies and a favourable mix shift toward higher-margin
    subscriptions. Operating expenses reflected continued investment in
    market expansion and platform research.

    Adjusted operating margin came in slightly ahead of the guidance
    range. Cash and equivalents at quarter-end provide a healthy runway
    at the current operating cadence.

    Guidance for the next quarter anticipates revenue modestly above the
    current level with a stable margin profile. Full-year guidance is
    unchanged.
    """
    return BenignDoc(f"finance_{idx:03d}", "finance", text,
                     {"title": f"{co} Quarterly Summary"})


def _academic(r: random.Random, idx: int) -> BenignDoc:
    topic = r.choice([
        "retrieval-augmented generation", "graph neural networks",
        "differential privacy", "federated learning",
        "neural information retrieval", "program synthesis",
        "causal inference", "representation learning",
    ])
    text = f"""
    A Survey of {topic.title()} for Knowledge-Intensive Tasks

    Abstract
    We survey recent advances in {topic} and their application to
    knowledge-intensive natural language tasks. We compare parametric and
    non-parametric approaches, evaluate them on standard benchmarks, and
    analyse the trade-offs between accuracy, latency, and robustness.

    Our analysis indicates that {topic} approaches are robust to corpus
    size but sensitive to the quality of the underlying components.
    Jointly optimising components yields consistent improvements over
    optimising either in isolation.

    We release our experiment configuration and evaluation code to
    facilitate reproducibility. We hope this work encourages broader
    exploration of {topic} across related research areas.
    """
    return BenignDoc(f"academic_{idx:03d}", "academic", text,
                     {"title": f"Survey of {topic.title()}"})


def _support_ticket(r: random.Random, idx: int) -> BenignDoc:
    name = f"{r.choice(_FIRST)} {r.choice(_LAST)}"
    comp = r.choice(["dashboard", "export", "login", "billing page",
                     "report builder", "API client", "mobile app"])
    text = f"""
    Support Ticket #{r.randint(10000, 99999)}

    Reporter: {name}
    Component: {comp}
    Priority: Normal

    Description
    The {comp} occasionally takes longer than expected to load when the
    account has a large number of records. The page eventually renders
    correctly but the delay is noticeable. This started after the most
    recent update.

    Steps to reproduce: open the {comp}, apply the default filters, and
    observe the load time on an account with several thousand records.

    Expected: the {comp} loads within a couple of seconds.
    Actual: the {comp} takes noticeably longer under heavy data volume.

    Resolution notes: the engineering team added pagination and a server-
    side index. The reporter confirmed the issue is resolved after the
    fix was deployed. Closing the ticket as resolved.
    """
    return BenignDoc(f"ticket_{idx:03d}", "support", text,
                     {"title": f"Ticket from {name}"})


def _csv_like(r: random.Random, idx: int) -> BenignDoc:
    rows = ["name,role,department,location,start_year"]
    for _ in range(r.randint(8, 20)):
        rows.append(
            f"{r.choice(_FIRST)} {r.choice(_LAST)},"
            f"{r.choice(['Engineer','Analyst','Manager','Designer','Lead'])},"
            f"{r.choice(['Platform','Data','Product','Security','Finance'])},"
            f"{r.choice(_CITY)},{r.randint(2015, 2026)}"
        )
    text = "\n".join(rows)
    return BenignDoc(f"csv_{idx:03d}", "csv", text,
                     {"title": "Employee Roster Export"})


def _readme(r: random.Random, idx: int) -> BenignDoc:
    lang = r.choice(_LANG)
    name = r.choice(["pipeline-kit", "schema-tools", "metric-collector",
                     "config-loader", "retry-helper", "trace-bridge"])
    text = f"""
    # {name}

    A small {lang} library for {r.choice(_DOMAIN)}. It focuses on a clean
    API, predictable performance, and good defaults.

    ## Installation
    Use your language's standard package manager to add {name} as a
    dependency. There are no required external services.

    ## Quick Start
    Import the client, construct it with the default configuration, and
    call the primary entry point with your input. The result object
    carries the status and any diagnostics.

    ## Configuration
    Configuration is read from the environment with sensible defaults.
    Every option is documented in the configuration reference. Nothing
    is sent off the machine; all processing is local.

    ## Contributing
    Contributions are welcome. Please open an issue to discuss larger
    changes before submitting a pull request. Run the test suite before
    submitting.

    ## License
    Released under a permissive open-source license. See the LICENSE
    file for details.
    """
    return BenignDoc(f"readme_{idx:03d}", "readme", text,
                     {"title": f"{name} README"})


def _marketing(r: random.Random, idx: int) -> BenignDoc:
    co = r.choice(_COMPANY)
    prod = r.choice(["CloudStore", "DataLake", "InsightHub", "FlowEngine",
                     "SecureVault", "MetricBoard"])
    ver = f"{r.randint(2,6)}.0"
    pct = r.randint(15, 45)
    text = f"""
    Introducing {co} {prod} {ver} — Faster and More Secure

    Today we are excited to announce the general availability of {prod}
    {ver}, the most significant update to our platform in recent memory.

    What's New

    Intelligent Tiering: A new engine analyses access patterns and moves
    data between tiers automatically, reducing cost by an average of
    {pct}% in customer pilots.

    Context-Aware Access: Every request is evaluated against a policy
    engine that factors in identity, device posture, and data
    classification, replacing coarse access lists with fine-grained
    controls.

    Faster Replication: Cross-region replication latency dropped
    substantially, enabling active-active architectures for globally
    distributed applications.

    Getting Started: Existing customers can upgrade via the self-service
    wizard in the console. New customers can start a free trial. Our
    solutions team is available to help plan a migration.
    """
    return BenignDoc(f"marketing_{idx:03d}", "marketing", text,
                     {"title": f"{prod} {ver} Launch"})


_TEMPLATES = [
    _resume, _contract, _tech_doc, _policy, _finance,
    _academic, _support_ticket, _csv_like, _readme, _marketing,
]


def generate_corpus(count: int = 220, seed: int = 20260515) -> list[BenignDoc]:
    """Return `count` deterministic benign documents (default 220 ≥ 200)."""
    docs: list[BenignDoc] = []
    base = _rng(seed)
    for i in range(count):
        tmpl = _TEMPLATES[i % len(_TEMPLATES)]
        # Derive a per-doc RNG so each document is independent yet stable.
        sub = _rng(seed + i * 7919)
        docs.append(tmpl(sub, i))
    return docs


if __name__ == "__main__":
    corpus = generate_corpus()
    print(f"generated {len(corpus)} benign documents")
    cats: dict[str, int] = {}
    for d in corpus:
        cats[d.category] = cats.get(d.category, 0) + 1
    for c, n in sorted(cats.items()):
        print(f"  {c:12} {n}")
