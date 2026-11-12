"""pytest 公共夹具：把项目根目录加入 sys.path，每个测试使用临时数据库。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import db  # noqa: E402


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "test.db"
    db.init_db(path)
    yield str(path)
