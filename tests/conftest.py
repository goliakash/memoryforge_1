import pytest
from backend.app.memory.hindsight_engine import hindsight
from backend.app.memory.storage import incident_store

@pytest.fixture(autouse=True)
def reset_test_state():
    hindsight.reset_memory()
    incident_store.clear()
    yield
    hindsight.reset_memory()
    incident_store.clear()
