"""Single authoritative ODMM edition registry. Author: Abdelhalim Talbi."""
FULL_NAME = "Open Data Migration Manager"
RELEASE = "228.0"
EDITIONS = {
    "linux-full": {"name": "Open Data Migration Manager — Linux Full", "version": "228.0", "platform": "linux", "mode": "full", "migration_engine": "native", "execution": "server", "entry": "ODMM-LINUX-FULL-V2280.sh"},
    "linux-compact": {"name": "Open Data Migration Manager — Linux Compact", "version": "7.9.0", "platform": "linux", "mode": "compact", "migration_engine": "native", "execution": "read-only-supervision", "entry": "ODMM-LINUX-COMPACT-V2280.sh"},
    "windows-compact": {"name": "Open Data Migration Manager — Windows Compact", "version": "7.9.0", "platform": "windows", "mode": "compact", "migration_engine": "native-server", "execution": "read-only-supervision", "entry": "BUILD-WINDOWS-COMPACT-V2280.cmd"},
}
def edition(key):
    return dict(EDITIONS[key])
