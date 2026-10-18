"""Pure bounded pagination for Windows Compact; never mutates source jobs."""
PAGE_SIZE = 200

def paginate(items, page=0, size=PAGE_SIZE):
    if not isinstance(items, list) or not isinstance(page, int) or not isinstance(size, int) or size < 1 or size > 1000:
        raise ValueError("Invalid pagination parameters")
    count = max(1, (len(items) + size - 1) // size)
    page = min(max(page, 0), count - 1)
    return items[page * size:(page + 1) * size], page, count

def sort_jobs(items, column="id", reverse=False):
    if column not in ("id", "status"):
        raise ValueError("Unsupported sort column")
    return sorted(items, key=lambda item: str(item.get(column, "")).casefold(), reverse=reverse)
