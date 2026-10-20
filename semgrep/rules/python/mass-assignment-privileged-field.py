# Fixtures for the mass-assignment-privileged-field rule.
#
# Annotations follow the semgrep test convention: the "ruleid" comment marks a
# line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
#
# The first case is reduced from erev0s/VAmPI api_views/users.py register_user().
# It is the shape that matters: the request value is laundered through a local
# and a branch before it reaches the constructor, so a syntactic rule keyed on
# `admin=request.json[...]` would miss it. Hence taint mode.

from flask import request

from models import User, db


# --- privilege escalation via the request body ------------------------------


def register_user_KNOWN_FALSE_NEGATIVE():
    """VAmPI's real register_user(). This rule does NOT catch it, by design.

    The request value controls the *branch*, not the *value*: `admin` ends up
    holding a boolean literal, so taint analysis is correct that it carries no
    taint. Catching this needs control-dependence (implicit flow), which
    Semgrep's taint engine does not track and which is a well-known limit of
    taint analysis generally.

    The `ok` annotation below asserts current behaviour honestly. It is a
    recorded miss, not a desirable non-finding. See the README.
    """
    request_data = request.get_json()
    if "admin" in request_data:
        if request_data["admin"]:
            admin = True
        else:
            admin = False
        # ok: mass-assignment-privileged-field
        user = User(username=request_data["username"], email=request_data["email"], admin=admin)
        db.session.add(user)


def register_direct():
    # ruleid: mass-assignment-privileged-field
    user = User(username=request.get_json()["username"], is_admin=request.get_json()["is_admin"])
    return user


def update_profile_attr():
    body = request.get_json()
    user = User.query.first()
    # ruleid: mass-assignment-privileged-field
    user.role = body["role"]
    db.session.commit()


def blind_splat():
    body = request.get_json()
    # ruleid: mass-assignment-privileged-field
    user = User(**body)
    return user


def setattr_loop():
    body = request.get_json()
    user = User.query.first()
    for key in body:
        # ruleid: mass-assignment-privileged-field
        setattr(user, key, body[key])


def form_source_counts_too():
    # ruleid: mass-assignment-privileged-field
    user = User(username=request.form["username"], verified=request.form["verified"])
    return user


def wallet_balance_from_body():
    body = request.get_json()
    account = User.query.first()
    # ruleid: mass-assignment-privileged-field
    account.balance = body["balance"]


# --- safe: client never reaches a privileged field --------------------------


def register_allowlisted():
    """Only non-privileged fields are read out of the body."""
    body = request.get_json()
    # ok: mass-assignment-privileged-field
    user = User(username=body["username"], email=body["email"], password=body["password"])
    db.session.add(user)


def register_with_server_default():
    """The privileged field is set by the server, not the caller."""
    body = request.get_json()
    # ok: mass-assignment-privileged-field
    user = User(username=body["username"], email=body["email"], admin=False)
    db.session.add(user)


def promote_by_internal_policy(target_username):
    """Privileged field set from a server-side decision, no request taint."""
    user = User.query.filter_by(username=target_username).first()
    # ok: mass-assignment-privileged-field
    user.role = compute_role_from_directory(user)
    db.session.commit()


def explicit_allowlist_loop():
    body = request.get_json()
    user = User.query.first()
    for key in ("username", "email", "bio"):
        if key in body:
            # ok: mass-assignment-privileged-field
            setattr(user, key, body[key])


def non_privileged_attr_from_body():
    body = request.get_json()
    user = User.query.first()
    # ok: mass-assignment-privileged-field
    user.bio = body["bio"]
    db.session.commit()


def compute_role_from_directory(user):
    return "member"
