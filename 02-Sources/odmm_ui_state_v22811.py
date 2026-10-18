"""Pure UI state rules: stale refreshes must never replace current data."""
def resolve_refresh(current_rows, request_id, active_id, incoming, error, validator):
    if request_id != active_id:
        return current_rows, "STALE"
    if error:
        return current_rows, "ERROR"
    try:
        validator(incoming)
    except (ValueError, TypeError):
        return current_rows, "INVALID"
    return list(incoming), "OK"

def selection_after_filter(selected_ids, visible_rows):
    visible_ids = {str(row.get("id", "")) for row in visible_rows}
    return set(selected_ids) & visible_ids
