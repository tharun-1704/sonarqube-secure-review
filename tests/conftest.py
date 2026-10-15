"""Load both app versions side by side, each with its own throwaway database."""
import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# The fixed app refuses to start without a secret from the environment.
os.environ.setdefault("FLASK_SECRET_KEY", "test-only-secret")


def load_app(name, folder):
    spec = importlib.util.spec_from_file_location(name, ROOT / folder / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_client(module, tmp_path):
    module.DB_PATH = str(tmp_path / "users.db")
    module.init_db()
    module.app.config["TESTING"] = True
    return module.app.test_client()


@pytest.fixture
def vuln(tmp_path):
    module = load_app("vuln_app", "app-vulnerable")
    return module, make_client(module, tmp_path)


@pytest.fixture
def fixed(tmp_path):
    module = load_app("fixed_app", "app-fixed")
    return module, make_client(module, tmp_path)
