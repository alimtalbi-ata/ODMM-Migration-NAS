"""Single authoritative ODMM edition registry. Author: Abdelhalim Talbi."""
FULL_NAME = "Open Data Migration Manager"
RELEASE = "227.8"
EDITIONS = {
    "linux-full": {"name": "Open Data Migration Manager — Linux Full", "version": "227.8", "platform": "linux", "mode": "full", "migration_engine": "native", "execution": "server", "entry": "ODMM-LINUX-FULL-V2278.sh"},
    "linux-compact": {"name": "Open Data Migration Manager — Linux Compact", "version": "7.8.8", "platform": "linux", "mode": "compact", "migration_engine": "native", "execution": "read-only-supervision", "entry": "ODMM-LINUX-COMPACT-V2278.sh"},
    "windows-compact": {"name": "Open Data Migration Manager — Windows Compact", "version": "7.8.8", "platform": "windows", "mode": "compact", "migration_engine": "native-server", "execution": "read-only-supervision", "entry": "BUILD-WINDOWS-COMPACT-V2278.cmd"},
}
def edition(key):
    return dict(EDITIONS[key])
