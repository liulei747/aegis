"""Request handler - untrusted entry point."""

import sqlite3

from service import load_user
from util import safe_escape


def handle_request(request):
    user_id = request.args.get("id")
    name = safe_escape(user_id)
    return load_user(name)


def unused_helper(value):
    return value


class Controller:
    def dispatch(self, request):
        return handle_request(request)
