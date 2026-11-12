"""SQLite 访问层：批次、Finding、告警实例、人工复核记录。

表结构：
- batches   扫描批次（before/after），记录来源文件、目标、规则集与文件哈希
- findings  漏洞主表，按稳定指纹唯一；保留首次/最近发现批次与处置信息
- alerts    每次扫描出现的实例（同一 Finding 可在多个批次重复出现）
- reviews   人工复核记录：判定、理由、证据备注
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT UNIQUE NOT NULL,
    kind          TEXT NOT NULL,            -- before / after / manual
    source_file   TEXT,
    target        TEXT,
    ruleset       TEXT,
    note          TEXT,
    sha256        TEXT,
    imported_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint      TEXT UNIQUE NOT NULL,
    pluginid         TEXT NOT NULL,
    name             TEXT,
    riskcode         INTEGER DEFAULT 0,
    cwe              TEXT,
    first_batch_id   INTEGER,
    last_batch_id    INTEGER,
    status           TEXT NOT NULL DEFAULT 'New',
    owner            TEXT,
    branch           TEXT,
    commit_sha       TEXT,
    review_reason    TEXT,
    rescan_batch_id  INTEGER,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    FOREIGN KEY (first_batch_id)  REFERENCES batches(id),
    FOREIGN KEY (last_batch_id)   REFERENCES batches(id),
    FOREIGN KEY (rescan_batch_id) REFERENCES batches(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    batch_id    INTEGER NOT NULL,
    uri         TEXT,
    method      TEXT,
    param       TEXT,
    evidence    TEXT,
    riskcode    INTEGER DEFAULT 0,
    seen_at     TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (batch_id)   REFERENCES batches(id)
);

CREATE TABLE IF NOT EXISTS reviews (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL,
    reviewer      TEXT,
    verdict       TEXT NOT NULL,   -- Confirmed / False Positive / Accepted Risk
    reason        TEXT,
    evidence_note TEXT,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_finding ON alerts(finding_id);
CREATE INDEX IF NOT EXISTS idx_alerts_batch   ON alerts(batch_id);
"""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def connect(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    path = Path(db_path or config.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[Path | str] = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def reset_db(db_path: Optional[Path | str] = None) -> None:
    path = Path(db_path or config.DB_PATH)
    if path.exists():
        path.unlink()
    init_db(path)


# ---------- 批次 ----------

def add_batch(label: str, kind: str, source_file: str = "", target: str = "",
              ruleset: str = "", note: str = "", sha256: str = "",
              db_path: Optional[Path | str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO batches(label, kind, source_file, target, ruleset, note, sha256, imported_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (label, kind, source_file, target, ruleset, note, sha256, _now()),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_batches(db_path: Optional[Path | str] = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM batches ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_batch(batch_id: int, db_path: Optional[Path | str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
    return dict(row) if row else None


# ---------- Finding ----------

def find_by_fingerprint(fp: str, db_path: Optional[Path | str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE fingerprint=?", (fp,)).fetchone()
    return dict(row) if row else None


def insert_finding(fp: str, alert: dict, batch_id: int,
                   db_path: Optional[Path | str] = None) -> int:
    now = _now()
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO findings
               (fingerprint, pluginid, name, riskcode, cwe, first_batch_id, last_batch_id,
                status, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                fp, alert["pluginid"], alert["name"], alert["riskcode"], alert["cwe"],
                batch_id, batch_id, "New", now, now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def touch_finding(finding_id: int, batch_id: int, riskcode: int,
                  db_path: Optional[Path | str] = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE findings SET last_batch_id=?, riskcode=?, updated_at=?
               WHERE id=?""",
            (batch_id, riskcode, _now(), finding_id),
        )
        conn.commit()


def get_finding(finding_id: int, db_path: Optional[Path | str] = None) -> Optional[dict]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    return dict(row) if row else None


def list_findings(status: Optional[str] = None, risk: Optional[str] = None,
                  owner: Optional[str] = None, db_path: Optional[Path | str] = None) -> list[dict]:
    sql = "SELECT * FROM findings WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status=?"
        params.append(status)
    if risk:
        sql += " AND riskcode=?"
        params.append(config.RISK_CODE[risk])
    if owner:
        sql += " AND owner=?"
        params.append(owner)
    sql += " ORDER BY riskcode DESC, id"
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def update_finding(finding_id: int, fields: dict,
                   db_path: Optional[Path | str] = None) -> dict:
    """更新处置字段。Verified 必须同时有 commit 与复扫批次，否则拒绝。"""
    finding = get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"Finding {finding_id} 不存在")

    merged = {**finding, **fields}
    if merged["status"] == "Verified":
        if not (merged.get("commit_sha") or "").strip():
            raise ValueError("置为 Verified 前必须填写修复 Commit")
        if not merged.get("rescan_batch_id"):
            raise ValueError("置为 Verified 前必须关联复扫批次（after 证据）")

    allowed = {"owner", "status", "branch", "commit_sha", "review_reason", "rescan_batch_id"}
    sets = [f"{k}=?" for k in fields if k in allowed]
    if not sets:
        return finding
    params = [fields[k] for k in fields if k in allowed]
    params.append(_now())
    params.append(finding_id)
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE findings SET {', '.join(sets)}, updated_at=? WHERE id=?",
            params,
        )
        conn.commit()
    return get_finding(finding_id, db_path)


# ---------- 告警实例 ----------

def add_alert(finding_id: int, batch_id: int, alert: dict,
              db_path: Optional[Path | str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO alerts(finding_id, batch_id, uri, method, param, evidence, riskcode, seen_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                finding_id, batch_id, alert["uri"], alert["method"], alert["param"],
                alert["evidence"], alert["riskcode"], _now(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_alerts(finding_id: Optional[int] = None, batch_id: Optional[int] = None,
                db_path: Optional[Path | str] = None) -> list[dict]:
    sql = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if finding_id is not None:
        sql += " AND finding_id=?"
        params.append(finding_id)
    if batch_id is not None:
        sql += " AND batch_id=?"
        params.append(batch_id)
    sql += " ORDER BY id"
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def fingerprints_in_batch(batch_id: int, db_path: Optional[Path | str] = None) -> dict[str, dict]:
    """返回 {fingerprint: finding 摘要}，风险等级取该批次告警实例记录，用于批次对比。"""
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT f.*, a.riskcode AS batch_riskcode FROM findings f
               JOIN alerts a ON a.finding_id=f.id
               WHERE a.batch_id=?""",
            (batch_id,),
        ).fetchall()
    result: dict[str, dict] = {}
    for r in rows:
        item = dict(r)
        item["riskcode"] = item["batch_riskcode"]
        result[r["fingerprint"]] = item
    return result


# ---------- 复核记录 ----------

def add_review(finding_id: int, reviewer: str, verdict: str, reason: str,
               evidence_note: str = "", db_path: Optional[Path | str] = None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO reviews(finding_id, reviewer, verdict, reason, evidence_note, created_at)
               VALUES (?,?,?,?,?,?)""",
            (finding_id, reviewer, verdict, reason, evidence_note, _now()),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_reviews(finding_id: Optional[int] = None,
                 db_path: Optional[Path | str] = None) -> list[dict]:
    sql = "SELECT * FROM reviews"
    params: list = []
    if finding_id is not None:
        sql += " WHERE finding_id=?"
        params.append(finding_id)
    sql += " ORDER BY id"
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]
