import asyncio
import json
from pathlib import Path

from app.intel import (
    import_exploitdb,
    import_github_advisories,
    import_kev,
    import_nvd,
    import_osv,
    import_wordfence,
)


class DummySession:
    async def commit(self) -> None:
        return None


def test_wordfence_import_one_record(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wordfence.json"
    path.write_text(
        json.dumps(
            {
                "uuid-1": {
                    "id": "wf-100",
                    "cve": "CVE-2026-5000",
                    "title": "Elementor issue",
                    "description": "Plugin vulnerability",
                    "references": ["https://example.com/advisory"],
                    "cvss": {"rating": "high", "score": 8.1},
                    "published": "2026-04-01T00:00:00Z",
                    "updated": "2026-04-02T00:00:00Z",
                    "software": [
                        {
                            "type": "plugin",
                            "name": "Elementor",
                            "slug": "elementor",
                            "affected_versions": {
                                "range-1": {
                                    "from_version": "3.0.0",
                                    "to_version": "3.35.5",
                                }
                            },
                            "patched_versions": ["3.35.6"],
                            "remediation": "Update Elementor.",
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    rows: list[dict] = []

    async def fake_upsert_wordfence_vulnerability(session, **payload):
        rows.append(payload)
        return payload

    monkeypatch.setattr(
        import_wordfence,
        "upsert_wordfence_vulnerability",
        fake_upsert_wordfence_vulnerability,
    )
    monkeypatch.setattr(
        import_wordfence,
        "finalize_import",
        lambda *args, **kwargs: asyncio.sleep(0, result=None),
    )

    asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))

    assert rows[0]["slug"] == "elementor"
    assert rows[0]["software_type"] == "plugin"
    assert rows[0]["affected_version_start"] == "3.0.0"
    assert rows[0]["affected_version_end"] == "3.35.5"
    assert rows[0]["patched_version"] == "3.35.6"
    assert rows[0]["remediation"] == "Update Elementor."


def test_wordfence_import_with_null_cve(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wordfence.json"
    path.write_text(
        json.dumps(
            {
                "uuid-2": {
                    "id": "wf-101",
                    "cve": None,
                    "title": "Theme issue",
                    "software": [
                        {
                            "type": "theme",
                            "slug": "hello-elementor",
                            "affected_versions": {
                                "range-1": {"from_version": "1.0.0", "to_version": "1.0.1"}
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    rows: list[dict] = []

    async def fake_upsert_wordfence_vulnerability(session, **payload):
        rows.append(payload)
        return payload

    monkeypatch.setattr(
        import_wordfence,
        "upsert_wordfence_vulnerability",
        fake_upsert_wordfence_vulnerability,
    )
    monkeypatch.setattr(
        import_wordfence,
        "finalize_import",
        lambda *args, **kwargs: asyncio.sleep(0, result=None),
    )

    asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))

    assert rows[0]["cve_id"] is None


def test_wordfence_from_version_star_becomes_null(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wordfence.json"
    path.write_text(
        json.dumps(
            {
                "uuid-3": {
                    "id": "wf-102",
                    "title": "Plugin issue",
                    "software": [
                        {
                            "type": "plugin",
                            "slug": "elementor",
                            "affected_versions": {
                                "range-1": {"from_version": "*", "to_version": "3.35.5"}
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    rows: list[dict] = []

    async def fake_upsert_wordfence_vulnerability(session, **payload):
        rows.append(payload)
        return payload

    monkeypatch.setattr(
        import_wordfence,
        "upsert_wordfence_vulnerability",
        fake_upsert_wordfence_vulnerability,
    )
    monkeypatch.setattr(
        import_wordfence,
        "finalize_import",
        lambda *args, **kwargs: asyncio.sleep(0, result=None),
    )

    asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))

    assert rows[0]["affected_version_start"] is None
    assert rows[0]["affected_version_end"] == "3.35.5"


def test_wordfence_duplicate_import_rerun(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wordfence.json"
    path.write_text(
        json.dumps(
            {
                "uuid-4": {
                    "id": "wf-103",
                    "title": "Theme issue",
                    "software": [
                        {
                            "type": "theme",
                            "slug": "hello-elementor",
                            "affected_versions": {
                                "range-1": {"from_version": "1.0.0", "to_version": "1.0.1"}
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    calls = {"rows": 0}

    async def fake_upsert_wordfence_vulnerability(session, **payload):
        calls["rows"] += 1
        return payload

    monkeypatch.setattr(
        import_wordfence,
        "upsert_wordfence_vulnerability",
        fake_upsert_wordfence_vulnerability,
    )
    monkeypatch.setattr(
        import_wordfence,
        "finalize_import",
        lambda *args, **kwargs: asyncio.sleep(0, result=None),
    )

    asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))
    asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))

    assert calls["rows"] == 2


def test_wordfence_import_summary(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wordfence.json"
    path.write_text(
        json.dumps(
            {
                "uuid-5": {
                    "id": "wf-104",
                    "title": "Plugin issue",
                    "software": [
                        {
                            "type": "plugin",
                            "slug": "elementor",
                            "affected_versions": {
                                "range-1": {"from_version": "3.0.0", "to_version": "3.35.5"}
                            },
                        }
                    ],
                },
                "uuid-6": {
                    "id": "wf-105",
                    "title": "Missing software",
                },
            }
        ),
        encoding="utf-8",
    )

    async def fake_upsert_wordfence_vulnerability(session, **payload):
        return payload

    monkeypatch.setattr(
        import_wordfence,
        "upsert_wordfence_vulnerability",
        fake_upsert_wordfence_vulnerability,
    )
    monkeypatch.setattr(
        import_wordfence,
        "finalize_import",
        lambda *args, **kwargs: asyncio.sleep(0, result=None),
    )

    summary = asyncio.run(import_wordfence.import_wordfence_file(DummySession(), path))

    assert summary == {
        "records_read": 2,
        "software_entries_imported": 1,
        "skipped_records": 1,
    }


def test_parse_cpe23_criteria() -> None:
    vendor, product_name, version = import_nvd.parse_cpe23_criteria(
        "cpe:2.3:a:opentext:firstclass:5.50:*:*:*:*:*:*:*"
    )

    assert vendor == "opentext"
    assert product_name == "firstclass"
    assert version == "5.50"


def test_parse_cpe23_criteria_ignores_wildcard_version() -> None:
    vendor, product_name, version = import_nvd.parse_cpe23_criteria(
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    )

    assert vendor == "nginx"
    assert product_name == "nginx"
    assert version is None


def test_nvd_import_creates_vuln_record_and_products(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "nvd.json"
    path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-0001",
                            "descriptions": [{"lang": "en", "value": "NVD description"}],
                            "published": "2026-01-01T00:00:00Z",
                            "lastModified": "2026-01-02T00:00:00Z",
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {"baseScore": 9.8},
                                        "baseSeverity": "CRITICAL",
                                    }
                                ]
                            },
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:a:opentext:firstclass:5.50:*:*:*:*:*:*:*",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    recorded: dict[str, list[dict]] = {"records": [], "products": []}

    async def fake_upsert_vuln_record(session, **payload):
        recorded["records"].append(payload)
        return type("Record", (), {"id": 1})()

    async def fake_upsert_alias(session, **payload):
        return payload

    async def fake_upsert_product(session, **payload):
        recorded["products"].append(payload)
        return payload

    async def fake_finalize(session):
        return None

    monkeypatch.setattr(import_nvd, "upsert_vuln_record", fake_upsert_vuln_record)
    monkeypatch.setattr(import_nvd, "upsert_alias", fake_upsert_alias)
    monkeypatch.setattr(import_nvd, "upsert_affected_product", fake_upsert_product)
    monkeypatch.setattr(import_nvd, "finalize_import", fake_finalize)

    asyncio.run(import_nvd.import_nvd_file(DummySession(), path))

    assert recorded["records"][0]["primary_id"] == "CVE-2026-0001"
    assert recorded["products"][0]["product"].vendor == "opentext"
    assert recorded["products"][0]["product"].product_name == "firstclass"
    assert recorded["products"][0]["product"].version_exact == "5.50"


def test_nvd_import_ignores_non_vulnerable_matches(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "nvd.json"
    path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-0007",
                            "descriptions": [{"value": "desc"}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": False,
                                                    "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    product_calls = {"count": 0}

    monkeypatch.setattr(import_nvd, "upsert_vuln_record", lambda *args, **kwargs: asyncio.sleep(0, result=type("Record", (), {"id": 7})()))
    monkeypatch.setattr(import_nvd, "upsert_alias", lambda *args, **kwargs: asyncio.sleep(0, result=None))

    async def fake_upsert_product(session, **payload):
        product_calls["count"] += 1
        return payload

    monkeypatch.setattr(import_nvd, "upsert_affected_product", fake_upsert_product)
    monkeypatch.setattr(import_nvd, "finalize_import", lambda *args, **kwargs: asyncio.sleep(0, result=None))

    asyncio.run(import_nvd.import_nvd_file(DummySession(), path))

    assert product_calls["count"] == 0


def test_kev_json_import_one_record(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "title": "Known Exploited Vulnerabilities Catalog",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-39987",
                        "vendorProject": "Marimo",
                        "product": "Marimo",
                        "vulnerabilityName": "Auth bypass",
                        "dateAdded": "2026-04-23",
                        "shortDescription": "Short desc",
                        "requiredAction": "Patch now",
                        "dueDate": "2026-05-07",
                        "knownRansomwareCampaignUse": "Unknown",
                        "notes": "Extra notes",
                        "cwes": ["CWE-306"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    kev_rows: list[dict] = []
    vuln_rows: list[dict] = []

    async def fake_upsert_kev_entry(session, **payload):
        kev_rows.append(payload)
        return payload

    async def fake_upsert_vuln_record(session, **payload):
        vuln_rows.append(payload)
        return type("Record", (), {"id": 10})()

    monkeypatch.setattr(import_kev, "upsert_kev_entry", fake_upsert_kev_entry)
    monkeypatch.setattr(import_kev, "upsert_vuln_record", fake_upsert_vuln_record)
    monkeypatch.setattr(import_kev, "upsert_alias", lambda *args, **kwargs: asyncio.sleep(0, result=None))
    monkeypatch.setattr(import_kev, "finalize_import", lambda *args, **kwargs: asyncio.sleep(0, result=None))

    asyncio.run(import_kev.import_kev_file(DummySession(), path))

    assert kev_rows[0]["cve_id"] == "CVE-2026-39987"
    assert kev_rows[0]["vendor_project"] == "Marimo"
    assert kev_rows[0]["required_action"] == "Patch now"
    assert vuln_rows[0]["has_kev"] is True


def test_kev_json_rerun_is_idempotent_enough(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-39988",
                        "vendorProject": "Vendor",
                        "product": "Product",
                        "vulnerabilityName": "Bug",
                        "dateAdded": "2026-04-23",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    calls = {"kev": 0}

    async def fake_upsert_kev_entry(session, **payload):
        calls["kev"] += 1
        return payload

    monkeypatch.setattr(import_kev, "upsert_kev_entry", fake_upsert_kev_entry)
    monkeypatch.setattr(import_kev, "upsert_vuln_record", lambda *args, **kwargs: asyncio.sleep(0, result=type("Record", (), {"id": 11})()))
    monkeypatch.setattr(import_kev, "upsert_alias", lambda *args, **kwargs: asyncio.sleep(0, result=None))
    monkeypatch.setattr(import_kev, "finalize_import", lambda *args, **kwargs: asyncio.sleep(0, result=None))

    asyncio.run(import_kev.import_kev_file(DummySession(), path))
    asyncio.run(import_kev.import_kev_file(DummySession(), path))

    assert calls["kev"] == 2


def test_kev_has_kev_propagation_to_matching_vuln_record(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-39989",
                        "vendorProject": "Vendor",
                        "product": "Product",
                        "vulnerabilityName": "Bug",
                        "dateAdded": "2026-04-23",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    vuln_rows: list[dict] = []

    async def fake_upsert_vuln_record(session, **payload):
        vuln_rows.append(payload)
        return type("Record", (), {"id": 12})()

    monkeypatch.setattr(import_kev, "upsert_kev_entry", lambda *args, **kwargs: asyncio.sleep(0, result=None))
    monkeypatch.setattr(import_kev, "upsert_vuln_record", fake_upsert_vuln_record)
    monkeypatch.setattr(import_kev, "upsert_alias", lambda *args, **kwargs: asyncio.sleep(0, result=None))
    monkeypatch.setattr(import_kev, "finalize_import", lambda *args, **kwargs: asyncio.sleep(0, result=None))

    asyncio.run(import_kev.import_kev_file(DummySession(), path))

    assert vuln_rows[0]["cve_id"] == "CVE-2026-39989"
    assert vuln_rows[0]["has_kev"] is True


def test_duplicate_import_behavior_is_safe_enough(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "nvd.json"
    path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-0006",
                            "descriptions": [{"value": "dup"}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    seen: set[str] = set()
    calls = {"records": 0, "products": 0}
