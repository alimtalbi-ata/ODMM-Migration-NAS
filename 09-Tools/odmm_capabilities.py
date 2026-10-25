#!/usr/bin/env python3
"""ODMM Linux lab capability report (strictly evidence-scoped).

Do not equate successful local POSIX CI with NAS, NFSv4 or SMB qualification.
Author: Abdelhalim Talbi.
"""
import argparse
import json

CAPABILITIES = {
    "local_posix_single_file_copy": {"status": "lab_qualified", "evidence": "09-Tools/test_odmm_local_lab_cli.py"},
    "local_posix_directory_tree_copy": {"status": "lab_qualified", "evidence": "09-Tools/test_odmm_local_tree_cli.py"},
    "local_posix_content_integrity": {"status": "lab_qualified", "evidence": "09-Tools/test_odmm_tree_verifier_negative.py"},
    "local_posix_mode_preservation": {"status": "lab_qualified", "evidence": "09-Tools/test_odmm_local_tree_cli.py"},
    "local_posix_crash_quarantine": {"status": "lab_qualified", "evidence": "09-Tools/odmm_real_local_tree_smoke.py"},
    "nfs_v3_v4_migration": {"status": "not_qualified", "evidence": None},
    "smb_ntfs_acl_migration": {"status": "not_qualified", "evidence": None},
    "nfs_v4_acl_fidelity": {"status": "not_qualified", "evidence": None},
    "uid_gid_sid_identity_mapping": {"status": "not_qualified", "evidence": None},
    "nas_multiserver_failover": {"status": "not_qualified", "evidence": None},
    "production_recovery_resume": {"status": "not_qualified", "evidence": None},
}


def main():
    p = argparse.ArgumentParser(description="Print scoped ODMM capability evidence")
    p.add_argument("--require", choices=sorted(CAPABILITIES))
    args = p.parse_args()
    print(json.dumps({"scope": "isolated Linux local POSIX lab",
                      "production_nas_qualified": False,
                      "capabilities": CAPABILITIES}, sort_keys=True, indent=2))
    if args.require and CAPABILITIES[args.require]["status"] != "lab_qualified":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
