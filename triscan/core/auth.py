"""Login / registration gate for the TriScan CLI (users live in the Django DB)."""
from __future__ import annotations

import time

from core import db, ui

MAX_ATTEMPTS = 3


def _register(first: bool = False):
    from django.contrib.auth.models import User
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError

    ui.title("Create account" if not first else "First run — create the admin account")
    while True:
        username = ui.ask("Choose a username")
        if not username:
            ui.warn("Username cannot be empty.")
            continue
        if User.objects.filter(username__iexact=username).exists():
            ui.warn("That username is taken.")
            continue
        break
    for _ in range(MAX_ATTEMPTS):
        pw = ui.ask_secret("Choose a password (min 8 chars)")
        pw2 = ui.ask_secret("Repeat password")
        if pw != pw2:
            ui.warn("Passwords do not match.")
            continue
        try:
            validate_password(pw)
        except ValidationError as e:
            for m in e.messages:
                ui.warn(m)
            continue
        user = User.objects.create_user(username=username, password=pw,
                                        is_staff=first, is_superuser=first)
        ui.ok(f"Account '{username}' created.")
        return user
    ui.err("Too many failed attempts.")
    return None


def _login():
    from django.contrib.auth import authenticate
    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = ui.ask("Username")
        password = ui.ask_secret("Password")
        user = authenticate(username=username, password=password)
        db.log_login(username, bool(user))
        if user and user.is_active:
            ui.ok(f"Welcome back, {user.username}.")
            return user
        left = MAX_ATTEMPTS - attempt
        ui.err("Invalid username or password." + (f" {left} attempt(s) left." if left else ""))
        time.sleep(min(2 * attempt, 5))   # slow down guessing
    return None


def gate():
    """Return an authenticated User, or None if the user quits / fails."""
    from django.contrib.auth.models import User

    ui.banner("Secure login")
    if not User.objects.exists():
        ui.info("No users exist yet.")
        return _register(first=True)

    while True:
        print()
        print(f"  {ui.c('[L]', 'bcyan')} Login     {ui.c('[R]', 'bcyan')} Register new user     {ui.c('[Q]', 'bcyan')} Quit")
        choice = ui.ask("Choose", "L").lower()[:1]
        if choice == "q":
            return None
        if choice == "r":
            user = _register()
            if user:
                return user
        elif choice == "l":
            user = _login()
            if user:
                return user
            return None
