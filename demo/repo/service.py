"""Domain service."""

from repo import query_user


def load_user(user_id):
    return query_user(user_id)


def unused_service_helper():
    return 42
