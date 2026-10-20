"""Linux multi-node topology validation regression tests."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_node_inventory import TopologyError, validate_topology

def topology():
    return {"schema_version": 1, "nodes": [
        {"name": "control-1", "address": "10.1.0.1", "roles": ["control", "registry"], "site": "paris", "networks": []},
        {"name": "mover-1", "address": "10.1.0.2", "roles": ["datamover"], "site": "paris", "networks": ["nas-a"]},
    ]}

class InventoryTests(unittest.TestCase):
    def test_valid_topology_never_claims_live_readiness(self):
        result = validate_topology(topology())
        self.assertFalse(result["ready_for_live_migration"])
        self.assertEqual(len(result["nodes"]), 2)

    def test_duplicate_ip_refused(self):
        data = topology()
        data["nodes"][1]["address"] = "10.1.0.1"
        with self.assertRaisesRegex(TopologyError, "DUPLICATE_ADDRESS"):
            validate_topology(data)

    def test_missing_datamover_network_refused(self):
        data = topology()
        data["nodes"][1]["networks"] = []
        with self.assertRaisesRegex(TopologyError, "DATAMOVER_NETWORK_REQUIRED"):
            validate_topology(data)

    def test_missing_required_role_refused(self):
        data = topology()
        data["nodes"][0]["roles"] = ["control"]
        with self.assertRaisesRegex(TopologyError, "MISSING_REQUIRED_ROLES"):
            validate_topology(data)

    def test_bad_address_refused(self):
        data = topology()
        data["nodes"][0]["address"] = "host.example"
        with self.assertRaisesRegex(TopologyError, "INVALID_ADDRESS"):
            validate_topology(data)

if __name__ == "__main__":
    unittest.main()
