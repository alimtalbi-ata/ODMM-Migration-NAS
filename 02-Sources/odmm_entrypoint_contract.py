"""ODMM edition entrypoint contract, release V228.18. No migration execution."""
from pathlib import Path
import json
EDITION_CONTRACT = {
 "linux-full": {"name":"Open Data Migration Manager — Linux Full", "mode":"server", "launcher":"03-Build-Installation/ODMM-LINUX-FULL-V22812.sh", "launcher_role":"qualification-script", "platform":"linux", "qualified_native_runtime":False},
 "linux-compact": {"name":"Open Data Migration Manager — Linux Compact", "mode":"read-only-supervision", "launcher":"02-Sources/odmm_linux_compact_v22811.py", "launcher_role":"cli-wrapper", "platform":"linux", "qualified_native_runtime":False},
 "windows-compact": {"name":"Open Data Migration Manager — Windows Compact", "mode":"read-only-supervision", "launcher":"03-Build-Installation/BUILD-WINDOWS-COMPACT-V22811.cmd", "launcher_role":"build-script", "platform":"windows", "qualified_native_runtime":False},
}
def verify_contract(root):
 root=Path(root)
 issues=[]; editions={}
 for key, item in EDITION_CONTRACT.items():
  launcher=root/item['launcher']
  exists=launcher.is_file()
  if not exists: issues.append({'edition':key,'issue':'missing_launcher','file':item['launcher']})
  editions[key]={**item,'launcher_exists':exists}
 return {'schema':'odmm.entrypoint-contract.v1','release':'228.18','editions':editions,'issues':issues,'pass':not issues}
