# Fixtures for the missing-object-authorization rule.
#
# Annotations follow the semgrep test convention: the "ruleid" comment marks a
# line the rule MUST flag, the "ok" comment marks a line it MUST NOT flag.
#
# The shapes here are reduced from the real handlers in erev0s/VAmPI
# (api_views/books.py, api_views/users.py). Each vulnerable case is paired with
# the safe branch that sits beside it in the same upstream function, which is
# what makes this rule worth writing: the two differ by one keyword argument.

from flask import request

from models import Book, User, db


def token_claims(header):
    return {"sub": "someone"}


# --- BOLA: object loaded by a path parameter, no ownership constraint --------


def get_by_title(book_title):
    claims = token_claims(request.headers.get("Authorization"))
    # ruleid: missing-object-authorization
    book = Book.query.filter_by(book_title=str(book_title)).first()
    return book


def update_password(username):
    claims = token_claims(request.headers.get("Authorization"))
    # ruleid: missing-object-authorization
    user = User.query.filter_by(username=username).first()
    user.password = request.get_json()["password"]
    db.session.commit()


def get_book_pk(book_id):
    # ruleid: missing-object-authorization
    return Book.query.get(int(book_id))


def get_book_legacy_session(book_id):
    # ruleid: missing-object-authorization
    return db.session.query(Book).filter_by(id=book_id).first()


# --- Safe: the query is narrowed to the authenticated principal --------------


def get_by_title_safe(book_title):
    claims = token_claims(request.headers.get("Authorization"))
    owner = User.query.filter_by(username=claims["sub"]).first()
    # ok: missing-object-authorization
    book = Book.query.filter_by(user=owner, book_title=str(book_title)).first()
    return book


def update_password_safe(username):
    claims = token_claims(request.headers.get("Authorization"))
    # ok: missing-object-authorization
    user = User.query.filter_by(username=claims["sub"]).first()
    user.password = request.get_json()["password"]
    db.session.commit()


def update_email_safe(username):
    """Handler takes an id parameter but never keys the query on it."""
    claims = token_claims(request.headers.get("Authorization"))
    # ok: missing-object-authorization
    user = User.query.filter_by(username=claims["sub"]).first()
    user.email = request.get_json()["email"]
    db.session.commit()


def get_book_scoped_session(book_id):
    owner = User.query.filter_by(username=token_claims(None)["sub"]).first()
    # ok: missing-object-authorization
    return db.session.query(Book).filter_by(user_id=owner.id, id=book_id).first()


def list_my_books():
    """No request-controlled parameter at all."""
    claims = token_claims(request.headers.get("Authorization"))
    # ok: missing-object-authorization
    owner = User.query.filter_by(username=claims["sub"]).first()
    # ok: missing-object-authorization
    return Book.query.filter_by(user=owner).all()


# --- data layer, not a route handler ----------------------------------------
#
# These are reduced from VAmPI models/user_model.py, where they were the rule's
# only false positives before the staticmethod guard was added. A model helper
# has no business enforcing authorization; its caller does. Flagging it moves
# the finding away from the place the fix belongs.


class UserModel:
    @staticmethod
    def get_user(username):
        # ok: missing-object-authorization
        return User.query.filter_by(username=username).first()

    @staticmethod
    def delete_user(username):
        # ok: missing-object-authorization
        return User.query.filter_by(username=username).delete()

    @classmethod
    def find_by_title(cls, book_title):
        # ok: missing-object-authorization
        return Book.query.filter_by(book_title=str(book_title)).first()
