import pytest
from backend.app.memory.hindsight_engine import LocalHindsightEngine, HindsightMemoryEngine
from backend.app.models.memory import MemoryNetworkType

def test_hindsight_baseline_world_network():
    engine = LocalHindsightEngine()
    world_units = engine.networks[MemoryNetworkType.WORLD]
    assert len(world_units) >= 3
    assert any("SOC 2" in u["title"] for u in world_units)
    assert any("NIST" in u["title"] for u in world_units)

def test_four_tier_memory_networks():
    engine = HindsightMemoryEngine()
    assert MemoryNetworkType.WORLD in engine.networks
    assert MemoryNetworkType.EXPERIENCE in engine.networks
    assert MemoryNetworkType.OBSERVATION in engine.networks
    assert MemoryNetworkType.OPINION in engine.networks
