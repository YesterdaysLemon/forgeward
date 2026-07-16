from __future__ import annotations

from pathlib import Path

import pytest

from forgeward.config import initialize_project, load_config
from forgeward.models import ForgeWardConfig


@pytest.fixture
def project(tmp_path: Path) -> Path:
    initialize_project(tmp_path)
    return tmp_path


@pytest.fixture
def config(project: Path) -> ForgeWardConfig:
    return load_config(project)
