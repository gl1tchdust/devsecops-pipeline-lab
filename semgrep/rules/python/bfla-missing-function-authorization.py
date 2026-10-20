# Fixtures for the bfla-missing-function-authorization rule.
#
# Annotations follow the semgrep test convention: the "ruleid" comment marks a
# line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
#
# The first two cases are reduced from erev0s/VAmPI api_views/users.py, where
# /users/v1/_debug returns every user record including passwords and takes no
# credential at all.

from flask import jsonify, request

from models import User

# --- privileged operation, no authorization anywhere ------------------------


def debug():
    # ruleid: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users_debug()})


def get_all_users():
    # ruleid: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users()})


def nuke_user(username):
    # ruleid: bfla-missing-function-authorization
    User.delete_user(username)
    return "", 204


def promote(username):
    # ruleid: bfla-missing-function-authorization
    User.promote_to_admin(username)
    return "", 204


def purge_everything():
    # ruleid: bfla-missing-function-authorization
    User.purge_all()
    return "", 204


# --- authorization present: in-body check -----------------------------------


def delete_user_guarded(username):
    """VAmPI's safe shape: validate the token, then assert the admin role."""
    resp = token_validator(request.headers.get("Authorization"))
    if "error" in resp:
        return "", 401
    actor = User.query.filter_by(username=resp["sub"]).first()
    if not actor.admin:
        return "", 403
    # ok: bfla-missing-function-authorization
    User.delete_user(username)
    return "", 204


def list_users_with_role_helper():
    require_role("admin")
    # ok: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users()})


def list_users_with_permission_helper():
    check_permission("users:read")
    # ok: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users()})


def list_users_with_authorize_helper():
    authorize("users:read")
    # ok: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users()})


# --- authorization present: decorator ---------------------------------------


@login_required
def list_users_decorated():
    # ok: bfla-missing-function-authorization
    return jsonify({"users": User.get_all_users()})


@admin_required
def purge_decorated():
    # ok: bfla-missing-function-authorization
    User.purge_all()
    return "", 204


@permission_required("users:delete")
def delete_decorated(username):
    # ok: bfla-missing-function-authorization
    User.delete_user(username)
    return "", 204


# --- not a privileged operation, so out of scope ----------------------------


def login():
    """Public by necessity. The rule keys on the operation, not on the absence
    of an auth check, which is exactly why public endpoints stay quiet."""
    body = request.get_json()
    # ok: bfla-missing-function-authorization
    user = User.query.filter_by(username=body["username"]).first()
    return jsonify({"token": issue(user)})


def me():
    resp = token_validator(request.headers.get("Authorization"))
    # ok: bfla-missing-function-authorization
    user = User.query.filter_by(username=resp["sub"]).first()
    return jsonify({"username": user.username})


def token_validator(header):
    return {"sub": "someone"}


def require_role(role):
    return True


def check_permission(perm):
    return True


def authorize(perm):
    return True


def issue(user):
    return "token"


def login_required(fn):
    return fn


def admin_required(fn):
    return fn


def permission_required(perm):
    return lambda fn: fn


# --- data layer, not a route handler ----------------------------------------


class UserModel:
    @staticmethod
    def get_all_users():
        # ok: bfla-missing-function-authorization
        return [u for u in User.query.all()]

    @staticmethod
    def json_debug(user):
        """A serialiser whose name ends in _debug. Not a privileged operation.
        The accessor regex was loosened to match /users/v1/_debug and caught
        this instead, which is why it is pinned to get_all* now."""
        # ok: bfla-missing-function-authorization
        return {"username": user.username, "password": user.password}
