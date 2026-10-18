"""Classify storage failures without leaking internal details. Author: Abdelhalim Talbi."""
import sqlite3
from fastapi import HTTPException


def map_review_storage_error(exc):
    """Return a stable, retry-safe HTTP error; never claim a failed write was rolled back."""
    if isinstance(exc, sqlite3.Error):
        return HTTPException(503, 'REVIEW_STORAGE_UNAVAILABLE_RECONCILE_BEFORE_RETRY')
    if isinstance(exc, (OSError, PermissionError)):
        return HTTPException(503, 'REVIEW_STORAGE_UNAVAILABLE_RECONCILE_BEFORE_RETRY')
    return None
