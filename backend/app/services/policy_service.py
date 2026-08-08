"""Security Configuration Assessment (SCA) query service.

Powers the benchmark dashboard: policy list, per-agent scan summaries and the
paginated checks table with search. All scans are resolved through the SCA
``Agent`` registry (``sca_agents``) and the most recent completed
``PolicyScan``, so summaries and check tables are driven by stored
``CheckResult`` evidence.
"""

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.sca import Agent, Policy, PolicyCheck, PolicyScan


class PolicyService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def policies(self) -> list[dict]:
        rows = self.db.execute(
            select(Policy).order_by(Policy.created_at)
        ).scalars().all()
        return [
            {
                "id": p.id,
                "slug": p.slug,
                "policy_id": p.policy_id,
                "name": p.name,
                "rows_per_page": p.rows_per_page,
                "framework": p.framework,
                "version": p.version,
                "platform": p.platform,
                "benchmark": p.benchmark,
                "publisher": p.publisher,
                "status": p.status,
                "enabled": p.enabled,
            }
            for p in rows
        ]

    def policy_detail(self, policy_id: str) -> dict:
        policy = self.db.get(Policy, policy_id)
        if policy is None:
            return {}
        checks = self.db.scalar(
            select(func.count())
            .select_from(PolicyCheck)
            .where(PolicyCheck.policy_id == policy.id)
        ) or 0
        return {
            "id": policy.id,
            "slug": policy.slug,
            "policy_id": policy.policy_id,
            "name": policy.name,
            "description": policy.description,
            "framework": policy.framework,
            "version": policy.version,
            "platform": policy.platform,
            "benchmark": policy.benchmark,
            "publisher": policy.publisher,
            "status": policy.status,
            "enabled": policy.enabled,
            "rows_per_page": policy.rows_per_page,
            "total_checks": checks,
        }

    def _agent(self, agent_code: str) -> Agent | None:
        return self.db.scalar(
            select(Agent).where(Agent.agent_code == agent_code)
        )

    def _latest_scan(self, policy: Policy, agent: Agent) -> PolicyScan | None:
        return self.db.scalar(
            select(PolicyScan)
            .where(
                PolicyScan.policy_id == policy.id,
                PolicyScan.agent_id == agent.id,
                PolicyScan.status == "completed",
            )
            .order_by(PolicyScan.end_scan.desc())
            .limit(1)
        )

    def policy_summary(self, policy_id: str, agent_code: str = "001") -> dict:
        policy = self.db.get(Policy, policy_id)
        if policy is None:
            return {}
        agent = self._agent(agent_code)
        empty = {
            "policy": policy.name,
            "passed": 0,
            "failed": 0,
            "not_applicable": 0,
            "score": 0,
            "end_scan": None,
            "total_checks": 0,
            "risk_score": 0,
            "critical_failures": 0,
            "high_failures": 0,
            "medium_failures": 0,
            "low_failures": 0,
        }
        if agent is None:
            return empty

        scan = self._latest_scan(policy, agent)
        if scan is None:
            return empty

        return {
            "policy": policy.name,
            "passed": scan.passed,
            "failed": scan.failed,
            "not_applicable": scan.not_applicable,
            "score": scan.score,
            "end_scan": scan.end_scan.isoformat() if scan.end_scan else None,
            "total_checks": scan.total_checks,
            "risk_score": scan.risk_score,
            "critical_failures": scan.critical_failures,
            "high_failures": scan.high_failures,
            "medium_failures": scan.medium_failures,
            "low_failures": scan.low_failures,
        }

    def policy_checks(
        self,
        policy_id: str,
        page: int = 1,
        per_page: int = 10,
        search: str = "",
    ) -> dict:
        policy = self.db.get(Policy, policy_id)
        empty = {
            "items": [],
            "total": 0,
            "page": page,
            "perPage": per_page,
            "totalPages": 1,
        }
        if policy is None:
            return empty

        q = search.strip().lower()
        query = select(PolicyCheck).where(PolicyCheck.policy_id == policy.id)
        if q:
            query = query.where(
                or_(
                    PolicyCheck.check_id.ilike(f"%{q}%"),
                    PolicyCheck.title.ilike(f"%{q}%"),
                    PolicyCheck.target.ilike(f"%{q}%"),
                    PolicyCheck.result.ilike(f"%{q}%"),
                    PolicyCheck.severity.ilike(f"%{q}%"),
                    PolicyCheck.category.ilike(f"%{q}%"),
                )
            )

        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        start = (safe_page - 1) * per_page

        rows = self.db.execute(
            query.order_by(PolicyCheck.check_id).offset(start).limit(per_page)
        ).scalars().all()

        return {
            "items": [
                {
                    "id": c.check_id,
                    "title": c.title,
                    "target": c.target,
                    "result": c.result,
                    "severity": c.severity,
                    "category": c.category,
                }
                for c in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
        }
