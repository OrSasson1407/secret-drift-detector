import pytest
from detector.sources import _hash


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_expected(*keys_values) -> dict[str, str]:
    """Build a hashed expected-secrets dict from alternating key, plaintext pairs."""
    it = iter(keys_values)
    return {k: _hash(v) for k, v in zip(it, it)}


def make_actual(*keys_values) -> dict[str, str]:
    """Build a hashed actual-secrets dict from alternating key, plaintext pairs."""
    return make_expected(*keys_values)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_db(tmp_path):
    """Return a path to a fresh SQLite DB in a temp directory."""
    return str(tmp_path / "test_drift.db")


@pytest.fixture
def sample_expected():
    return make_expected(
        "DATABASE_PASSWORD", "s3cr3t",
        "STRIPE_SECRET_KEY", "sk_live_abc",
        "REDIS_URL",         "redis://localhost:6379",
        "APP_NAME",          "myapp",
    )


@pytest.fixture
def sample_actual_clean(sample_expected):
    """Runtime matches expected exactly."""
    return dict(sample_expected)


@pytest.fixture
def sample_actual_with_drift(sample_expected):
    """Runtime has one changed value, one missing key, one extra key."""
    actual = dict(sample_expected)
    actual["DATABASE_PASSWORD"] = _hash("n3w_s3cr3t")   # changed
    del actual["STRIPE_SECRET_KEY"]                       # missing
    actual["GHOST_VAR"] = _hash("ghost")                  # extra
    return actual
