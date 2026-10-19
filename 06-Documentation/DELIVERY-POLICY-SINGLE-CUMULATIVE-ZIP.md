# ODMM — Single cumulative versioned ZIP delivery policy

Author: Abdelhalim Talbi

## Mandatory user-facing artifact
Every qualified version MUST publish exactly one primary versioned archive:
`ODMM-V<version>-Complete-Windows-Sources-Documentation.zip`.

The archive must contain in the same root:
- `binary/portable/ODMM-Compact.exe`: standalone Windows Compact application;
- `binary/installer/ODMM-Compact-Setup-V*.exe`: Windows installer;
- `02-Sources/`: cumulative source code;
- `03-Build-Installation/`: build, installation and validation scripts;
- `06-Documentation/`: updated documentation for the release;
- `09-Tools/`: tests and validation tools;
- `DELIVERY-MANIFEST.json`: SHA-256 of each included file and exact source Git SHA;
- `binary/WINDOWS-INSTALL-SMOKE.json`: native install/uninstall evidence.

A source-only ZIP does NOT meet this delivery contract. Publish only after Windows
build, native install/uninstall, ZIP manifest verification and crash-recovery
pipelines are green for the same commit. If any gate is pending or failed,
state that the release is not qualified and do not advertise a complete ZIP.

## Limitations
Windows Compact is read-only. Native POSIX engine is an unqualified prototype.
Windows CI proves build/start/install smoke tests, not cross-vendor NAS
migration, ACL preservation, SMB/NFS production safety or real Windows fleet
compatibility.

## Versioning
Keep application internal version distinct from cumulative release train when
needed, but identify both in the documentation. Preserve main history and
prefer a feature branch/PR for major refactoring.

## V228.87 — Direct GitHub Release download
The Windows qualification workflow now publishes the qualified cumulative ZIP
as a GitHub Release asset under tag `v228.87`, using the exact checked-out
commit. Publication refuses to overwrite an existing tag. The release is
marked prerelease because NAS migration/ACL fidelity is not production qualified.

Download URL after successful publication:
https://github.com/alimtalbi-ata/ODMM-Migration-NAS/releases/download/v228.87/ODMM-V228.87-Complete-Windows-Sources-Documentation.zip

GitHub Actions artifacts remain a secondary traceability channel. This direct
release URL avoids depending on ChatGPT sandbox download links.
