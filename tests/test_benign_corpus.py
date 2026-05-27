"""
tests/test_benign_corpus.py  —  B.17 False-Positive Hardening

Scans a synthetic corpus of realistic benign documents through the full
detector stack (balanced profile) and asserts zero false-positive findings
across every threat code.

Design principles:
  - Each document is ~150–300 words of realistic prose.
  - No text is repeated more than twice; no single content word exceeds 6%
    of total tokens, staying safely below the 8% ungated ATS threshold.
  - Texts that legitimately reference injection-adjacent vocabulary
    (security research, IT policy) are included to validate precision.
  - Target: FP rate = 0% on this corpus in the balanced profile.

Marks: @pytest.mark.benign
"""
from __future__ import annotations

import os
import sys
import unittest

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.ats_manipulation import ATSManipulationDetector
from doc_firewall.detectors.prompt_injection import PromptInjectionDetector
from doc_firewall.detectors.text_obfuscation import TextObfuscationDetector
from doc_firewall.detectors.metadata_injection import MetadataInjectionDetector
from doc_firewall.detectors.ranking_manipulation import RankingManipulationDetector
from doc_firewall.enums import ThreatID


def _parsed(text: str, metadata: dict | None = None) -> ParsedDocument:
    return ParsedDocument(
        file_path="benign_test.txt",
        file_type="txt",
        text=text,
        metadata=metadata or {},
    )


def _run_all(text: str, metadata: dict | None = None) -> list:
    """Run the core detector suite (no ML) on text and return all findings."""
    cfg = ScanConfig()
    doc = _parsed(text, metadata)
    findings = []
    for det in [
        ATSManipulationDetector(),
        PromptInjectionDetector(),
        TextObfuscationDetector(),
        MetadataInjectionDetector(),
        RankingManipulationDetector(),
    ]:
        findings.extend(det.run(doc, cfg))
    return findings


@pytest.mark.benign
class TestBenignCorpus(unittest.TestCase):
    """Zero false-positive assertions across a realistic benign document corpus."""

    def _assert_clean(self, text: str, label: str, metadata: dict | None = None) -> None:
        findings = _run_all(text, metadata)
        if findings:
            details = "; ".join(f"{f.threat_id.value}:{f.title!r}" for f in findings)
            self.fail(f"[{label}] Unexpected findings: {details}")

    # ── 1. Technical job description ─────────────────────────────────────

    def test_software_engineer_job_description(self) -> None:
        self._assert_clean(
            """
            Senior Software Engineer — Platform Infrastructure

            We are building the next generation of distributed systems at scale and are looking
            for an experienced engineer to join our infrastructure team. This role is focused on
            reliability, performance, and developer experience across our microservices platform.

            What you will do:
            Design and implement backend services using Go and Python. Own reliability for
            critical data pipeline components that process millions of events per day. Drive
            architectural decisions and mentor engineers across the team. Collaborate with
            product and design to ship features on a quarterly cadence.

            What we are looking for:
            Five or more years of professional software engineering experience. Proficiency in
            at least one of Go, Python, or Rust. Strong grasp of distributed systems concepts
            such as consensus, sharding, and eventual consistency. Experience with AWS or GCP
            cloud infrastructure. Solid understanding of Docker and Kubernetes.

            Nice to have: experience with Apache Kafka, Flink, or similar stream-processing
            frameworks. Familiarity with Prometheus, Grafana, and OpenTelemetry for observability.

            Our hiring process: a 30-minute introductory call, a take-home technical assessment,
            and two structured interviews. Every applicant receives a decision within ten
            business days.
            """,
            "software_engineer_jd",
        )

    # ── 2. Python-heavy technical blog post ──────────────────────────────

    def test_python_technical_blog_post(self) -> None:
        self._assert_clean(
            """
            Building a Fast Data Ingestion Pipeline with Python and Apache Kafka

            Modern data platforms require ingestion pipelines that can handle hundreds of
            thousands of events per second with sub-second end-to-end latency. This post walks
            through building such a pipeline using Python, Apache Kafka, and the Confluent client
            library.

            We start by defining our Avro schema, which gives us both backward and forward
            compatibility as our event structure evolves. The producer is a straightforward
            asyncio application that batches records and flushes on a configurable interval.

            On the consumer side, we use a consumer group with three partitions. Each partition
            is processed by a dedicated asyncio task, giving us horizontal scalability without
            threading complexity. Error handling uses an exponential back-off strategy with a
            dead-letter topic for messages that fail after three retries.

            Benchmarking on a four-core laptop with a local Kafka cluster shows a sustained
            throughput of 85,000 events per second at P99 latency of 18 milliseconds. Switching
            to batched Avro serialisation drops the per-event overhead by roughly 40%.

            The complete source code is available in the GitHub repository linked at the end of
            this post. Contributions and issue reports are welcome.
            """,
            "python_kafka_blog",
        )

    # ── 3. Legal contract excerpt ─────────────────────────────────────────

    def test_legal_contract_excerpt(self) -> None:
        self._assert_clean(
            """
            SOFTWARE LICENSE AGREEMENT

            This Software License Agreement ("Agreement") is entered into as of the Effective
            Date between Acme Corporation, a Delaware corporation ("Licensor"), and the entity
            identified in the Order Form ("Licensee").

            1. GRANT OF LICENSE. Subject to the terms and conditions of this Agreement, Licensor
            hereby grants to Licensee a non-exclusive, non-transferable, limited license to use
            the Software solely for Licensee's internal business purposes.

            2. RESTRICTIONS. Licensee shall not: (a) sublicense, sell, resell, transfer, assign,
            or otherwise dispose of the Software; (b) modify or make derivative works based upon
            the Software; (c) reverse engineer or decompile the Software.

            3. PAYMENT. Licensee agrees to pay the fees set forth in the Order Form. All fees are
            due within thirty days of the invoice date. Unpaid amounts accrue interest at 1.5%
            per month.

            4. CONFIDENTIALITY. Each party agrees to keep confidential and not to disclose to
            any third party the other party's Confidential Information without prior written
            consent.

            5. TERMINATION. Either party may terminate this Agreement upon written notice if the
            other party materially breaches any provision of this Agreement and fails to cure
            such breach within thirty days after receiving written notice of such breach.
            """,
            "legal_contract",
        )

    # ── 4. IT security policy (mentions "ignore", "system", "instructions") ──

    def test_it_security_policy_document(self) -> None:
        self._assert_clean(
            """
            Information Security Acceptable Use Policy — Version 3.2

            Purpose: This policy defines acceptable use of corporate information systems and
            data assets. All employees, contractors, and vendors with access to corporate
            systems must comply with this policy.

            Scope: This policy applies to all computing devices, network resources, and data
            owned or managed by the organisation, including cloud-hosted systems.

            Acceptable Use:
            Employees may use corporate systems for legitimate business purposes. Incidental
            personal use is permitted provided it does not interfere with business operations
            or consume significant resources. Employees should follow department-specific
            guidelines issued by their managers.

            Prohibited Activities:
            Unauthorised access to systems or data, circumventing access controls, installing
            unapproved software, sharing credentials, transmitting confidential data over
            unencrypted channels, or engaging in any activity that violates applicable law.

            Incident Reporting:
            Any suspected security incident — including phishing, malware, or unauthorised
            access — must be reported to the security team within four hours of discovery.
            Do not attempt to investigate or remediate a suspected incident independently;
            contact the security operations centre immediately.

            Violations of this policy may result in disciplinary action up to and including
            termination of employment and referral to law enforcement where appropriate.
            """,
            "it_security_policy",
        )

    # ── 5. Medical clinical report ────────────────────────────────────────

    def test_medical_clinical_report(self) -> None:
        self._assert_clean(
            """
            PATIENT DISCHARGE SUMMARY

            Attending Physician: Dr. Sarah Chen, MD
            Department: Internal Medicine
            Admission Date: 2026-04-15   Discharge Date: 2026-04-19

            Chief Complaint: Chest pain and shortness of breath on exertion.

            History of Present Illness: A 58-year-old male with a past medical history
            significant for hypertension and type 2 diabetes mellitus presented to the
            emergency department with a three-day history of progressive exertional chest
            discomfort radiating to the left shoulder, accompanied by mild dyspnoea.

            Physical Examination: Vital signs on admission: blood pressure 148/92 mmHg,
            heart rate 88 beats per minute, respiratory rate 18, oxygen saturation 97% on
            room air, temperature 36.8°C. Cardiovascular examination revealed regular rate
            and rhythm with no murmurs. Lungs were clear to auscultation bilaterally.

            Diagnostic Workup: Troponin I was initially 0.04 ng/mL and rose to 1.2 ng/mL
            at six hours, consistent with non-ST elevation myocardial infarction. ECG showed
            ST depression in leads V4–V6. Echocardiogram demonstrated preserved ejection
            fraction of 58% with mild anterior wall hypokinesis.

            Hospital Course: The patient underwent coronary angiography revealing 80%
            stenosis of the left anterior descending artery. Drug-eluting stent placement
            was performed without complications.

            Discharge Medications: Aspirin 81 mg daily, ticagrelor 90 mg twice daily,
            atorvastatin 40 mg nightly, metformin 1000 mg twice daily, lisinopril 10 mg
            daily.

            Follow-up: Cardiology clinic in two weeks. Cardiac rehabilitation referral placed.
            """,
            "medical_clinical_report",
        )

    # ── 6. Financial analysis report ─────────────────────────────────────

    def test_financial_analysis_report(self) -> None:
        self._assert_clean(
            """
            Q1 2026 Financial Performance Summary

            Revenue for the first quarter of 2026 reached $42.3 million, representing a
            year-over-year growth of 18.4% compared to $35.7 million in Q1 2025. Recurring
            revenue now accounts for 74% of total revenue, up from 68% in the prior year
            period, reflecting continued customer retention and expansion within existing
            accounts.

            Gross margin expanded by 210 basis points to 67.4%, driven primarily by
            infrastructure cost efficiencies from our cloud optimisation initiative and a
            favourable mix shift toward higher-margin software subscriptions.

            Operating expenses totalled $28.1 million. Sales and marketing spend increased
            15% as we invested in new market expansion activities in Europe and Asia-Pacific.
            Research and development expenditure of $11.2 million reflects continued investment
            in our core platform capabilities.

            Adjusted EBITDA for the quarter was $6.8 million, representing a margin of 16.1%,
            ahead of our guidance range of 14–15%. Cash and cash equivalents at quarter-end
            stood at $89.4 million, providing approximately 18 months of runway at current
            operating cadence.

            Guidance: For Q2 2026, management expects revenue in the range of $44–46 million
            and adjusted EBITDA margin of 15–17%. Full-year 2026 guidance is unchanged at
            revenue of $175–180 million.
            """,
            "financial_report",
        )

    # ── 7. Security research paper (quotes injection techniques) ─────────

    def test_security_research_paper(self) -> None:
        self._assert_clean(
            """
            Adversarial Inputs in Large Language Model Document Processing Pipelines

            Abstract: We survey the landscape of adversarial inputs targeting large language
            model (LLM) document ingestion pipelines. Unlike single-turn text attacks, document-
            based adversarial inputs exploit the gap between what a human sees in a document
            and what a language model extracts from it.

            Background: Retrieval-augmented generation (RAG) systems ingest documents into
            a vector store and retrieve relevant passages as context for LLM queries. Attackers
            who can influence the contents of ingested documents may manipulate model behaviour
            for all downstream users who query information derived from those documents.

            Attack Surface: The attack surface includes visible body text, embedded metadata
            fields, font-substituted characters, hidden layers, and whitespace-injected content.
            Each surface may carry adversarial text invisible to human reviewers but extractable
            by text processing libraries.

            Defences: Effective defences operate at the parsing layer before text reaches the
            model context window. Detection approaches include pattern matching against known
            adversarial phrase templates, statistical analysis of token distributions, and
            machine learning classifiers trained on adversarial document corpora.

            Conclusion: Document-layer adversarial attacks represent a meaningful and
            underappreciated risk in enterprise AI deployments. Defenders should apply
            content-aware scanning at every document intake point.
            """,
            "security_research_paper",
        )

    # ── 8. Cloud infrastructure runbook ──────────────────────────────────

    def test_cloud_infrastructure_runbook(self) -> None:
        self._assert_clean(
            """
            AWS Production Environment Runbook — Incident Response Procedures

            This runbook documents standard operating procedures for the production AWS
            environment. All on-call engineers must review this document before their first
            rotation shift.

            1. Alert Triage
            When a PagerDuty alert fires, acknowledge within five minutes. Access the
            Grafana dashboard at the URL pinned in the #oncall Slack channel. Determine
            whether the alert is a hard failure (service unavailable) or a soft degradation
            (elevated error rate or latency spike).

            2. ECS Service Recovery
            For a failed ECS task: navigate to the ECS console, identify the failing service,
            and check the stopped task logs in CloudWatch. Common causes include out-of-memory
            conditions (increase task memory limit in the task definition) or failed health
            checks (verify the /health endpoint is returning 200).

            3. Database Failover
            Aurora PostgreSQL is configured with automatic multi-AZ failover. Typical failover
            takes 30–60 seconds. During failover, application connection pools will experience
            brief errors. After failover completes, verify the writer endpoint resolves to the
            new primary instance and run the post-failover validation script.

            4. Rollback Procedure
            To roll back a deployment: identify the previous task definition revision in ECS,
            update the service to use the previous revision, and confirm that the deployment
            stabilises within five minutes. Notify the engineering channel and file an
            incident report within 24 hours.
            """,
            "cloud_runbook",
        )

    # ── 9. HR employee handbook excerpt ──────────────────────────────────

    def test_hr_employee_handbook(self) -> None:
        self._assert_clean(
            """
            Employee Handbook — Benefits and Compensation

            Health Benefits: All full-time employees are eligible for comprehensive medical,
            dental, and vision coverage. Coverage begins on the first day of the month
            following your start date. Employees may also enrol their dependents, including
            a spouse or domestic partner and children up to age 26.

            Retirement Savings: The company offers a 401(k) plan with a 4% employer match.
            You are eligible to contribute from your first day of employment. The employer
            match vests over a four-year schedule at 25% per year.

            Paid Time Off: Full-time employees accrue 15 days of paid vacation per year in
            the first two years, increasing to 20 days after two years of service. In addition,
            employees receive 10 paid public holidays and 5 paid sick days per year. Unused
            vacation days carry over to the following year up to a maximum of 30 days.

            Parental Leave: Primary caregivers receive 16 weeks of paid parental leave.
            Secondary caregivers receive 4 weeks. Leave may be taken at any time within
            the first 12 months after the birth, adoption, or foster placement of a child.

            Professional Development: Each employee receives an annual learning and development
            budget of $2,000. This may be used for conferences, courses, certifications, or
            books related to your role. Requests are submitted through the HR portal and
            approved by your manager.
            """,
            "hr_handbook",
        )

    # ── 10. Product documentation (legitimate "ignore" usage) ────────────

    def test_product_documentation(self) -> None:
        self._assert_clean(
            """
            DocFirewall SDK — Getting Started Guide

            Installation: Install the library using pip. The base installation includes all
            heuristic detectors. Optional dependencies unlock ML-based detection layers.

            Quick Start:
            Import the Scanner class and create an instance with the default configuration.
            Call scanner.scan() with the path to your document. The method returns a ScanReport
            containing the verdict, risk score, and a list of findings.

            Configuration Profiles:
            The balanced profile is recommended for most deployments. It enables YARA scanning,
            Aho-Corasick phrase matching, and all structural detectors. The strict profile adds
            the BERT-based classifier and steganography checks at the cost of higher latency.
            Use the lenient profile for trusted internal pipelines where throughput is critical.

            Interpreting Results:
            A verdict of ALLOW means no significant threats were detected. FLAG means the
            document warrants human review but is not definitively malicious. BLOCK means the
            document contains high-confidence threat indicators and should be rejected.

            Note: Do not ignore FLAG-verdict documents without review. In high-security
            deployments, configure the policy engine to escalate FLAG verdicts automatically.
            The audit log records every scan result for forensic purposes.
            """,
            "product_documentation",
        )

    # ── 11. Privacy policy ────────────────────────────────────────────────

    def test_privacy_policy(self) -> None:
        self._assert_clean(
            """
            Privacy Policy — Last updated 1 January 2026

            This Privacy Policy describes how Acme Inc. ("we", "us", or "our") collects,
            uses, and shares information about you when you use our services.

            Information We Collect: We collect information you provide directly to us, such
            as when you create an account, make a purchase, or contact us for support. We
            also collect information automatically when you use our services, including log
            data, device information, and cookies.

            How We Use Your Information: We use the information we collect to provide,
            maintain, and improve our services, process transactions, send you technical
            notices and support messages, and respond to your comments and questions.

            Information Sharing: We do not share your personal information with third parties
            except as described in this policy. We may share information with vendors who
            perform services on our behalf, such as payment processing and email delivery.

            Data Retention: We retain personal information for as long as necessary to provide
            our services and fulfil the purposes outlined in this policy, unless a longer
            retention period is required by law.

            Your Rights: Depending on your location, you may have the right to access, correct,
            or delete your personal information. To exercise these rights, please contact our
            privacy team at privacy@acme.example.com.
            """,
            "privacy_policy",
        )

    # ── 12. Data engineering resume ───────────────────────────────────────

    def test_data_engineering_resume(self) -> None:
        self._assert_clean(
            """
            Maria Santos — Data Engineer

            Professional Summary
            Data engineer with six years of experience designing and maintaining large-scale
            batch and streaming data pipelines. Comfortable across the full stack from raw
            ingestion through transformation and serving layers.

            Work Experience

            Senior Data Engineer — Dataflow Corp (2022–present)
            Led migration of legacy ETL workflows to Apache Airflow, reducing pipeline
            maintenance overhead by 30%. Designed a real-time fraud detection feature store
            using Flink and Redis. Mentored two junior engineers and contributed to internal
            platform documentation.

            Data Engineer — Analytics Ltd (2019–2022)
            Built and maintained batch pipelines processing 2 TB of e-commerce event data
            daily using Spark on EMR. Implemented data quality monitoring with Great
            Expectations. Collaborated with analysts to optimise slow SQL queries in Redshift.

            Education
            B.Sc. Computer Science — University of São Paulo (2018)
            Certified Google Professional Data Engineer (2021)

            Technical Skills
            Languages: SQL, Python, Scala
            Frameworks: Apache Spark, Flink, Airflow, Kafka, dbt
            Cloud: AWS (EMR, Glue, Redshift, S3), GCP (BigQuery, Dataflow)
            Tools: Docker, Kubernetes, Terraform, Git
            """,
            "data_engineer_resume",
        )

    # ── 13. Marketing copy ────────────────────────────────────────────────

    def test_marketing_copy(self) -> None:
        self._assert_clean(
            """
            Introducing Acme CloudStore 3.0 — Faster, Smarter, More Secure

            Today we are excited to announce the general availability of Acme CloudStore 3.0,
            the most significant update to our enterprise object storage platform in three years.

            What's New:

            Intelligent Tiering 2.0: Our new AI-powered tiering engine analyses access patterns
            across your entire data estate and automatically moves objects between storage tiers
            in real time, reducing storage costs by an average of 34% in our customer pilots.

            Zero-Trust Access Controls: Every object request is now evaluated against a
            context-aware policy engine that factors in user identity, device posture, network
            location, and data classification. This replaces bucket-level ACLs with granular,
            attribute-based access control.

            Instant Global Replication: Cross-region replication latency has dropped from
            minutes to under five seconds, enabling active-active architectures for globally
            distributed applications.

            Getting Started: Existing customers can upgrade via the self-service upgrade wizard
            in the management console. New customers can sign up for a free 30-day trial at
            our website. Our solutions engineering team is available to help design your
            migration plan.
            """,
            "marketing_copy",
        )

    # ── 14. Academic abstract ─────────────────────────────────────────────

    def test_academic_abstract(self) -> None:
        self._assert_clean(
            """
            Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks

            Abstract

            We explore retrieval-augmented generation (RAG), a general-purpose framework for
            grounding large language model outputs in external knowledge retrieved at inference
            time. Unlike approaches that encode knowledge entirely in model parameters, RAG
            systems retrieve relevant passages from a document corpus using a dense retrieval
            model and condition generation on the retrieved evidence.

            We evaluate RAG on a suite of knowledge-intensive question answering benchmarks,
            including Natural Questions, TriviaQA, and WebQuestions. RAG substantially
            outperforms parametric sequence-to-sequence models on all three benchmarks and
            approaches the performance of task-specific fine-tuned models, despite receiving
            no task-specific supervision.

            Analysis reveals that RAG's performance is robust to the size of the retrieval
            corpus and the number of retrieved passages, but sensitive to the quality of the
            retrieval model. Fine-tuning both the retrieval and generation components jointly
            yields further improvements over fine-tuning either component in isolation.

            We release our model weights, retrieval index, and evaluation code to facilitate
            future research in this area. We hope this work encourages broader exploration
            of retrieval-augmented approaches across natural language processing tasks beyond
            question answering.
            """,
            "academic_abstract",
        )

    # ── 15. Metadata fields that are long but legitimate ─────────────────

    def test_legitimate_long_metadata(self) -> None:
        self._assert_clean(
            "Annual performance review and compensation planning document for the fiscal year.",
            "long_metadata",
            metadata={
                "title": "FY2026 Performance Review — Engineering Organisation",
                "description": (
                    "This document contains the annual performance review summaries and "
                    "compensation planning decisions for all engineering staff. It is "
                    "intended for use by HR business partners and engineering managers only. "
                    "All information is confidential and subject to our data governance policy."
                ),
                "keywords": (
                    "performance review, compensation, engineering, annual, FY2026, "
                    "HR, salary, bonus, promotion, talent, management"
                ),
                "author": "HR Operations Team",
            },
        )

    # ── 16. Terms of service ──────────────────────────────────────────────

    def test_terms_of_service(self) -> None:
        self._assert_clean(
            """
            Terms of Service — Effective Date: 1 March 2026

            1. Acceptance of Terms
            By accessing or using our service, you agree to be bound by these Terms of
            Service and our Privacy Policy. If you do not agree to these terms, please do
            not use our service.

            2. Description of Service
            We provide an online platform for document management and collaboration. The
            service allows users to upload, store, share, and collaborate on documents in
            various formats.

            3. User Responsibilities
            You are responsible for maintaining the security of your account credentials.
            You agree not to use the service for any unlawful purpose or in any way that
            could damage, disable, or impair the service.

            4. Intellectual Property
            All content and materials available through the service, including but not
            limited to text, graphics, logos, and software, are the property of the company
            or its licensors and are protected by applicable intellectual property laws.

            5. Limitation of Liability
            To the maximum extent permitted by applicable law, the company shall not be
            liable for any indirect, incidental, special, consequential, or punitive damages
            arising out of or relating to your use of, or inability to use, the service.

            6. Governing Law
            These terms shall be governed by and construed in accordance with the laws of
            the State of Delaware, without regard to its conflict of law provisions.
            """,
            "terms_of_service",
        )


    # ── 17. SEO strategy document (legitimate ranking / manipulation vocab) ──
    #
    # R4: T5_RANKING_MANIPULATION weight is 0.6 — a single HIGH finding at
    # default confidence contributes 1-(1-0.6×0.8×0.5) = 0.24, just under
    # the FLAG threshold of 0.25.  This test confirms that a document
    # legitimately discussing search-engine ranking strategy does not fire T5.

    def test_seo_strategy_document(self) -> None:
        self._assert_clean(
            """
            Search Engine Optimisation Strategy — Q3 2026

            Executive Summary
            This document outlines the organic search strategy for the company's primary
            web presence. Our goal is to improve search engine rankings for high-intent
            commercial keywords while maintaining content quality and user experience.

            Current Ranking Performance
            As of June 2026, our domain holds a top-ten ranking for 142 target keywords,
            up from 98 in the prior quarter. The average position for our ten highest-traffic
            pages improved from 8.4 to 6.1. Click-through rate on branded search terms rose
            by 3.2 percentage points, indicating stronger brand recognition in the results page.

            Keyword Strategy
            We prioritise keywords at the intersection of high commercial intent and moderate
            competition. Long-tail phrases with clear purchase intent outperform broad head
            terms on a cost-per-acquisition basis. Content targeting informational queries
            supports top-of-funnel awareness and feeds the branded search pipeline.

            On-Page Optimisation
            Title tags and meta descriptions are being revised to improve click-through rates
            from the search results page. Internal linking is being audited to distribute
            authority from high-ranking hub pages to supporting cluster content. Page speed
            scores across our top-twenty landing pages have been improved by an average of
            14 points following image compression and script deferral.

            Link Building
            Outreach campaigns targeting industry publications and research organisations have
            generated 38 new referring domains this quarter. Domain authority as measured by
            third-party tools increased from 41 to 47. We continue to monitor for toxic links
            and disavow patterns that could negatively affect ranking stability.

            Next Steps
            Publish six new long-form articles targeting cluster keywords identified in the
            most recent content gap analysis. Complete the technical audit recommendations
            covering crawl budget, schema markup, and Core Web Vitals improvements.
            """,
            "seo_strategy_document",
        )

    # ── 18a. Real-world resume FP regressions ──────────────────────────────
    #
    # These exercise the false-positive surface we hit on a real resume
    # dataset (almost 100% FLAG/BLOCK rate). Each must produce zero findings
    # on the balanced profile.

    def test_resume_with_contact_hyperlinks(self) -> None:
        # mailto: + https://linkedin.com + https://github.com — every resume
        # has these. Hyperlinks alone must never trigger ranking/ATS findings.
        self._assert_clean(
            """
            Liam Patel — Full Stack Java Developer

            Contact
            Email: liam.patel@example.com
            LinkedIn: https://linkedin.com/in/liam-patel-9384
            GitHub: https://github.com/liampatel
            Phone: +1 (555) 234-9810

            Professional Summary
            Engineer who delivers meaningful impact as a Full Stack Java
            Developer. Eight years of experience designing scalable backend
            systems and modern web frontends across the JVM ecosystem and
            React. Comfortable owning a service end-to-end from design
            through on-call rotation.

            Work Experience

            Senior Engineer — Acme Inc (2022–present)
            Led the migration of a monolithic Java application to a set of
            Spring Boot microservices on Kubernetes. Designed the rollout
            plan, mentored two engineers, and shipped without downtime.

            Engineer — Helio Labs (2018–2022)
            Built and maintained order-management services in Java and
            Kotlin. Collaborated with product on roadmap planning and led
            interview loops for backend candidates.

            Education
            B.Sc. Computer Science — University of Lisbon (2017)

            Technical Skills
            Languages: Java, Kotlin, TypeScript, SQL
            Frameworks: Spring Boot, React, Hibernate, Kafka
            Tools: Docker, Kubernetes, Terraform, Git, GitHub Actions
            """,
            "resume_with_hyperlinks",
        )

    def test_pdf_extracted_text_with_structural_tokens(self) -> None:
        # Real PDFs occasionally leak structural keywords (endobj, endstream,
        # xref, etc.) into Docling-extracted text when fonts use embedded
        # CMaps. These tokens must not count toward keyword-stuffing
        # frequency checks.
        self._assert_clean(
            """
            Software Engineer Position — Job Description

            We are looking for a backend engineer to join the platform team.
            The role focuses on reliability, performance, and developer
            experience across our microservices. You will own services from
            design through on-call ownership.

            Responsibilities include designing distributed systems, writing
            clean and tested code, and mentoring teammates. We work in Go
            and Python on AWS infrastructure.

            obj endobj obj endobj obj endobj obj endobj obj endobj
            stream endstream stream endstream stream endstream
            xref trailer startxref obj endobj obj endobj obj endobj
            beginbfchar endbfchar beginbfchar endbfchar
            obj endobj obj endobj obj endobj obj endobj obj endobj
            obj endobj obj endobj obj endobj obj endobj obj endobj

            Compensation is competitive. Benefits include comprehensive
            health coverage, retirement matching, and an annual learning
            budget for professional development.
            """,
            "pdf_structural_token_leakage",
        )

    def test_pdf_extracted_text_with_numeric_coordinate_run(self) -> None:
        # Long runs of zero or numeric tokens from PDF graphics-state
        # matrices ("0 0 612 792 ...") must not fire T9 repeated-sequence.
        self._assert_clean(
            """
            Resume — Engineering Manager

            Strategic leader with experience scaling engineering teams from
            five to fifty across several quarters. Focus on hiring,
            coaching, and creating environments where engineers do their
            best work. Comfortable balancing roadmap delivery with
            investment in platform health.

            Recent Roles
            Director of Engineering — Northwind Systems (2023–present)
            Engineering Manager — Beacon Software (2019–2023)
            Tech Lead — Vertex Cloud (2016–2019)

            0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            0 0 612 792 0 0 1 0 0 1 0 0 0 0 612 792 0 0 1 0 0 1 0 0
            0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

            Selected Achievements
            Scaled the data platform organisation from eight to twenty-two
            engineers across two years while maintaining strong engagement
            scores. Led incident-response improvements that cut median
            time-to-resolution roughly in half year-over-year.
            """,
            "pdf_numeric_coordinate_run",
        )

    # ── 18d. Resume describing RAG / fetch systems near a contact URL ──────
    #
    # Real-world FP: software engineers who have built RAG / document-
    # ingestion pipelines describe that work on their resume, often near a
    # LinkedIn / GitHub link. The bare "URL within 500 chars of fetch verb"
    # rule for T10 indirect-injection false-fires on this. The tightened
    # rule (imperative-at-agent / politeness-marker / sentence-start) must
    # NOT match this passive-voice resume prose.

    def test_resume_with_rag_fetch_description(self) -> None:
        self._assert_clean(
            """
            Gliffton Mendes — Staff Software Engineer

            Contact
            Email: gliffton@example.com
            LinkedIn: https://www.linkedin.com/in/gliffton/
            GitHub: https://github.com/gliffton

            Selected Work

            HR AI Center of Excellence — Acme Inc (2024–present)
            Built a document-intake platform used by multiple teams to ingest
            documents with custom metadata defined per tenant. Designed the
            service to retrieve resume PDFs from S3, fetch the latest BERT
            classifier weights on startup, download tenant-specific YARA
            rules at runtime, and load configuration from a versioned
            object store. The system can pull data from upstream HRIS
            providers and read from on-premise file shares behind a VPN.

            Senior Engineer — Beacon Software (2021–2024)
            Maintained an ingestion pipeline that imports from third-party
            APIs and writes to a data warehouse. Implemented retry policies,
            dead-letter queues, and observability dashboards. Mentored two
            junior engineers and contributed to internal platform
            documentation.

            Technical Skills
            Languages: Python, Go, TypeScript
            Frameworks: FastAPI, React, LangChain, LlamaIndex
            """,
            "resume_with_rag_fetch_description",
        )

    # ── 18d-quad. PII detector must validate VIN / IBAN format
    #
    # Real-world FP: PDF internal object names (17-char alphanumeric like
    # "ParentTreeNextKey") false-fire the VIN regex. Timestamps like
    # "20260507001237Z00" too. Short mixed-case strings ("OF71M1C4n")
    # false-fire the IBAN regex. The tightened patterns now require:
    #   - VIN: explicit label prefix ("VIN:", "Vehicle ID:", "Chassis:")
    #   - IBAN: known ISO 3166-1 country code + ≥15 total chars + uppercase

    def test_pii_pdf_object_names_not_flagged_as_vin(self) -> None:
        self._assert_clean(
            "Document body. PDF internal: ParentTreeNextKey FontEncoderConfigA "
            "MarkInfoAnnotationRoot DocumentStructureTree. Timestamp 20260507001237Z00. "
            "Hash AABBCCDDEEFF11223. None of these are vehicle identification numbers "
            "or international bank account numbers — they are document internals "
            "and identifiers that happen to be 14-17 chars alphanumeric.",
            "pii_pdf_internals_not_vin_iban",
        )

    def test_pii_real_vin_with_label_still_fires(self) -> None:
        from doc_firewall.detectors.pii import PiiDetector
        from doc_firewall.enums import ThreatID
        cfg = ScanConfig()
        det = PiiDetector()
        doc = _parsed(
            "Vehicle history report. VIN: 1HGBH41JXMN109186 — 2021 Honda Civic. "
            "Owner verified the VIN matches the title."
        )
        findings = det.run(doc, cfg)
        assert any(
            f.threat_id == ThreatID.T8_METADATA_INJECTION
            and "VIN" in str(f.evidence.get("matches", {}))
            for f in findings
        ), f"Label-prefixed VIN should still fire; got {[f.evidence for f in findings]}"

    def test_pii_real_iban_still_fires(self) -> None:
        from doc_firewall.detectors.pii import PiiDetector
        from doc_firewall.enums import ThreatID
        cfg = ScanConfig()
        det = PiiDetector()
        # A real-format Norway IBAN (15 chars, country code NO)
        doc = _parsed(
            "Wire transfer details: please remit to IBAN NO9386011117947. "
            "Bank confirms account is active and accepting deposits."
        )
        findings = det.run(doc, cfg)
        assert any(
            f.threat_id == ThreatID.T8_METADATA_INJECTION
            and "IBAN" in str(f.evidence.get("matches", {}))
            for f in findings
        ), f"Real uppercase IBAN with valid country code should still fire; got {[f.evidence for f in findings]}"

    # ── 18d-quint. T9/T5 must skip Docling extraction artifacts
    #
    # Real-world FP: Docling inserts `<!-- image -->` placeholders at every
    # figure boundary when converting PDF/DOCX to markdown. A document with
    # many figures has "image" as the dominant content token. The pre-fix
    # frequency check called this "ATS keyword stuffing". The new
    # `_strip_extraction_noise` helper removes comments before counting.

    def test_t9_ignores_docling_image_placeholders(self) -> None:
        # Direct exercise of the noise-stripper: a focused unit test on the
        # frequency-counter path. A document with many `<!-- image -->`
        # placeholders should NOT register "image" as the dominant token.
        from doc_firewall.detectors.ats_manipulation import (
            _strip_extraction_noise,
        )
        # 30 Docling figure placeholders interleaved with varied prose
        text = "Quarterly performance review for the engineering organisation.\n"
        for i in range(30):
            text += f"Section {i}. The team delivered initiative {i} on schedule.\n<!-- image -->\n"
        stripped = _strip_extraction_noise(text)
        # After stripping, "image" should appear zero times
        assert "image" not in stripped.lower(), (
            f"Image placeholders not stripped: {stripped[:200]!r}"
        )
        # And `<!-- ... -->` should be gone
        assert "<!--" not in stripped

    # ── 18d-sext. T12 must not flag legitimate government contact info
    #
    # Real-world FP: IRS / state-agency / utility-bill documents combine
    # authority claims ("IRS", "Department of Motor Vehicles") with phone
    # contact info ("call us at 800-XXX-XXXX") — the old action_demand
    # regex matched "call us at" as a phishing CTA. Pruned in this release.

    def test_t12_ignores_legitimate_irs_contact_info(self) -> None:
        self._assert_clean(
            "Internal Revenue Service — Notice of Acceptance. Your election "
            "has been processed. Find tax forms or publications by visiting "
            "IRS.gov/Forms or by calling 800-TAX-FORM (800-829-3676). Call "
            "us at 800-829-4933 if you cannot find what you need online. If "
            "you prefer, you can write to the address at the top of this "
            "notice. This determination letter is for your records.",
            "t12_legitimate_irs_contact_info",
        )

    # ── 18d-sept. T10 indirect injection must not fire on "you can download"
    #
    # Real-world FP: IRS / government / customer-service docs say "You can
    # download X at https://...". The old agent-addressed pattern matched
    # "you" + "can" + "download" as an agent instruction. Tightened to
    # require AI/agent/model addressing with a directive modal.

    def test_t10_ignores_you_can_download_in_irs_doc(self) -> None:
        self._assert_clean(
            "Internal Revenue Service — EIN Confirmation. The service center "
            "will notify the LLC as to the acceptance or non-acceptance of "
            "its election. The LLC should generally receive a determination "
            "within 60 days after filing Form 8832 or Form 2553. "
            "You can download IRS forms, publications, and tax returns at "
            "https://www.irs.gov/formspubs. If you need to make changes to "
            "your organization's information, mail the information to the "
            "address provided at https://www.irs.gov/businesses.",
            "t10_you_can_download_irs",
        )

    # ── 18d-bis. Marketing / research doc that legitimately mentions
    # "system prompt" / "system instruction" / "reveal your X" must not
    # trigger T4 prompt-injection. These bare phrases were over-broad in
    # the fast-scan keyword list and false-fired on any LLM-security
    # content (research papers, this project's own marketing copy, etc.).

    def test_llm_security_marketing_copy(self) -> None:
        # Exercises the fast-scan-keyword fix: bare descriptive terms like
        # "system prompt", "system instruction", "reveal your X" must not
        # fire T4 on legitimate security / research / marketing content.
        # The test deliberately avoids quoting any actual adversarial phrase
        # (those *should* fire on the deep-scan detectors and are tested
        # elsewhere) — we only check that the descriptive terms alone are
        # not enough to escalate the verdict.
        self._assert_clean(
            """
            Secure Document Intake for LLM Pipelines.

            Modern AI applications process untrusted document uploads at
            scale. A poisoned document can exfiltrate the system prompt
            or trick the assistant into bypassing its guardrails.

            This guide describes the threat surface and shows how to wire
            our scanner into a LangChain or LlamaIndex pipeline. We cover
            attacks that try to reveal your model's hidden configuration,
            embed a system instruction in document metadata, or exfiltrate
            sensitive runtime state.

            Descriptive technical terms appear constantly in legitimate
            security content (whitepapers, research, marketing) and the
            scanner should not block on their bare presence — it must
            require a real adversarial phrase or behavior.
            """,
            "llm_security_marketing_copy",
        )

    # ── 18e. Metadata-injection detector must skip binary garbage ──────────
    #
    # Real-world FP: some PDFs leak undecoded compressed / encrypted stream
    # bytes into metadata fields like /Author. Short SQL-injection regexes
    # (``1=1``, ``select *``) coincidentally match in noise. The metadata
    # detector now requires fields to be ≥85% printable before running its
    # regex checks. Verify by passing a high-entropy binary blob as a
    # metadata title — it must NOT trigger script/SQL/T4 injection findings.

    def test_metadata_binary_garbage_not_flagged(self) -> None:
        self._assert_clean(
            "Resume content here. Normal English prose. No injection markers.",
            "metadata_binary_garbage",
            metadata={
                # 200 bytes of undecoded PDF stream content. Contains '1=1'
                # and other accidental SQL-shaped tokens in the binary noise.
                "title": (
                    "v]jj\x18>fOqvn2\x13v\xb8+\x1b6޸7&M2O{(!cb)\x03"
                    "iM5\x1eL6x$mF\x0c\x1a\x1f\x06?4~\x14\\\x1f\\o8q0ǘ"
                    "\x16$1=1Dpsp1#\x173\x0c\x080~\x162x*X\x14<k<Ld7}&1w"
                    "\x1dU\x14ٽ7;)@ B\x10Q@TĆ\x08\x14{>\x0bgħ"
                    "\t\x02O\xc3\xa9\xa1\x01\x02"
                ),
            },
        )

    # ── 19. Academic paper discussing ATS systems (legitimate T9 vocab) ────
    #
    # R4 companion: legitimate discussion of ATS manipulation in an academic
    # context should not trigger T9 or T5 detectors.

    def test_ats_academic_discussion(self) -> None:
        self._assert_clean(
            """
            Algorithmic Bias in Automated Hiring Systems: A Literature Review

            Abstract
            Automated applicant tracking systems (ATS) are widely deployed in enterprise
            hiring workflows. This review examines documented cases of algorithmic bias,
            keyword-matching limitations, and susceptibility to resume manipulation in
            commercially deployed ATS products.

            Background
            ATS platforms parse resume content and score candidates against job descriptions
            using keyword frequency, semantic similarity, and rule-based weighting. Research
            has shown that keyword stuffing — the deliberate repetition of high-value terms —
            can artificially inflate candidate scores in systems that weight raw term frequency
            without normalisation.

            Findings
            Studies of ten commercially deployed ATS platforms found that seven were
            susceptible to score inflation through term repetition at rates above eight percent
            of total token count. Ranking manipulation via synonym insertion was effective
            against four of the ten systems tested. Invisible text injection, where keywords
            are placed in white-on-white font, bypassed OCR-based extraction in three systems.

            Implications for Defenders
            Organisations deploying ATS systems should require vendors to document their
            normalisation and deduplication logic. Independent audits of scoring algorithms
            should be conducted annually. Document scanning for known manipulation patterns
            is an emerging best practice in enterprise HR security.

            Conclusion
            ATS manipulation remains an underappreciated attack surface in enterprise talent
            acquisition. Defenders require both technical controls and vendor accountability
            to maintain the integrity of algorithmic hiring decisions.
            """,
            "ats_academic_discussion",
        )


if __name__ == "__main__":
    unittest.main()
