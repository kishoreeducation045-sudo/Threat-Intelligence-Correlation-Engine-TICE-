import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from app.repository.report_repository import ReportRepository


def create_repo(retention_limit=1000, retention_days=7):
    tmp_dir = tempfile.TemporaryDirectory()
    path = os.path.join(tmp_dir.name, 'reports.db')
    repo = ReportRepository(db_path=path, retention_days=retention_days, retention_limit=retention_limit)
    return repo, tmp_dir


def test_save_and_fetch_recent_reports():
    repo, tmp_dir = create_repo()
    try:
        repo.save_analysis(
            ip_address='1.2.3.4',
            threat_score=90,
            risk_level='CRITICAL',
            abuse_confidence=95,
            total_reports=12,
            categories=['malware', 'botnet'],
            triggered_rules=['Rule A'],
            narrative='Critical threat detected.',
            country='US',
            asn='Example ASN',
            raw_data={'abuseipdb': {'score': 95}},
        )

        records = repo.get_recent(limit=10)
        assert len(records) == 1
        record = records[0]
        assert record['ip_address'] == '1.2.3.4'
        assert record['threat_score'] == 90
        assert record['risk_level'] == 'CRITICAL'
        assert record['is_new'] is True
        assert record['occurrence_count'] == 1
        assert record['raw_data']['abuseipdb']['score'] == 95
    finally:
        tmp_dir.cleanup()


def test_retention_limit_applies():
    repo, tmp_dir = create_repo(retention_limit=5)
    try:
        for idx in range(10):
            repo.save_analysis(
                ip_address=f'4.4.4.{idx}',
                threat_score=50,
                risk_level='MEDIUM',
                abuse_confidence=40,
                total_reports=idx,
                categories=['scanner'],
                triggered_rules=['Rule B'],
                narrative='Test entry',
                country='DE',
                asn='ASN',
                raw_data={'index': idx},
                analyzed_at=datetime.now(timezone.utc) - timedelta(minutes=idx),
            )
        records = repo.get_recent(limit=20)
        assert len(records) == 5
    finally:
        tmp_dir.cleanup()


def test_stats_generation():
    repo, tmp_dir = create_repo()
    try:
        now = datetime.now(timezone.utc)
        repo.save_analysis(
            ip_address='8.8.8.8',
            threat_score=80,
            risk_level='HIGH',
            abuse_confidence=70,
            total_reports=5,
            categories=['phishing'],
            triggered_rules=['Rule C'],
            narrative='High risk',
            country='US',
            asn='Google',
            raw_data={'example': True},
            analyzed_at=now,
        )
        repo.save_analysis(
            ip_address='9.9.9.9',
            threat_score=20,
            risk_level='LOW',
            abuse_confidence=5,
            total_reports=1,
            categories=['benign'],
            triggered_rules=[],
            narrative='Low risk',
            country='US',
            asn='Provider',
            raw_data={'example': False},
            analyzed_at=now - timedelta(hours=2),
        )

        stats = repo.get_stats(hours=24)
        assert stats['metrics']['total_reports'] == 2
        assert stats['metrics']['unique_ips'] == 2
        assert stats['risk_counts']['HIGH'] >= 1
        assert 'phishing' in stats['category_counts']
        assert isinstance(stats['report_volume'], list)
    finally:
        tmp_dir.cleanup()
