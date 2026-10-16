"""Tests for thimble (#2), run against synthetic Apps.

Run from the repository root:

    python3 -I tests/test_thimble.py

Nothing here touches a real App. Keys are generated at test time, GitHub's API is a
stub `curl`, `launchctl` is a stub, HOME is a temporary folder, and the clock is fixed
through THIMBLE_NOW. No assertion depends on a generated key's value.
"""

import atexit
import base64
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
THIMBLE = REPO / "bin" / "thimble"
HELPER = REPO / "bin" / "git-credential-thimble"
INSTALL = REPO / "install"

NOW = 1_700_000_000
ORG = "Synthetic-Org"
# The matching account sits in the middle, and no installation ID equals an App ID.
INSTALLATIONS = [
    {"id": 111, "account": {"login": "someone-else"}},
    {"id": 222, "account": {"login": ORG}},
    {"id": 333, "account": {"login": "another-org"}},
]
ALPHA_ID, BETA_ID, GAMMA_ID = 424242, 515151, 636363

LABEL = "com.asciizer0.thimble"
BLOCK_START = "# >>> thimble >>>"
BLOCK_END = "# <<< thimble <<<"
ZSHENV_BACKUP = ".zshenv.thimble-backup"


# --- Stubs on PATH ---------------------------------------------------------

STUB_CURL = r'''#!/usr/bin/env python3
# Stub for curl: records each call and answers like GitHub's App API.
import base64, json, os, sys

args = sys.argv[1:]
url = next(a for a in args if a.startswith("https://"))
method = "GET"
jwt = ""
for i, a in enumerate(args):
    nxt = args[i + 1] if i + 1 < len(args) else ""
    if a in ("-X", "--request"):
        method = nxt
    elif a.startswith("-X") and len(a) > 2:
        method = a[2:]
    elif a in ("-d", "--data", "--data-raw", "--json"):
        method = "POST"
    elif a in ("-H", "--header") and nxt.lower().startswith("authorization:"):
        jwt = nxt.split(":", 1)[1].strip().split(" ", 1)[-1]
with open(os.environ["STUB_CURL_LOG"], "a") as log:
    log.write(json.dumps({"url": url, "method": method, "jwt": jwt}) + "\n")

def iss():
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["iss"]

if "/access_tokens" in url:
    if os.environ.get("STUB_CURL_FAIL") == "access_tokens":
        print(json.dumps({"message": "Bad credentials", "status": "401"}))
        sys.exit(22 if ("--fail" in args or "-f" in args) else 0)
    installation = url.split("/app/installations/")[1].split("/")[0]
    print(json.dumps({"token": "ghs_FAKE_%s_%s" % (iss(), installation),
                      "expires_at": "2023-11-14T23:13:20Z"}))
elif "/app/installations" in url:
    print(os.environ["STUB_INSTALLATIONS"])
else:
    print(json.dumps({"message": "Not Found"}))
'''

STUB_LAUNCHCTL = r'''#!/bin/bash
# Stub for launchctl: records its arguments, one call per line.
printf '%s\n' "$*" >> "$STUB_LAUNCHCTL_LOG"
'''


# --- Builders and helpers --------------------------------------------------


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_parts(jwt):
    header, payload, signature = jwt.split(".")
    return (json.loads(b64url_decode(header)), json.loads(b64url_decode(payload)),
            (header + "." + payload).encode(), b64url_decode(signature))


class Keys:
    """RSA key pairs for the synthetic Apps, generated once for the whole run."""

    folder = None

    @classmethod
    def path(cls, name, public=False):
        if cls.folder is None:
            cls.folder = Path(tempfile.mkdtemp(prefix="thimble-keys-"))
            atexit.register(shutil.rmtree, cls.folder, True)
            for app in ("alpha", "beta", "gamma"):
                private = cls.folder / (app + ".pem")
                subprocess.run(["openssl", "genrsa", "-out", str(private), "2048"],
                               check=True, capture_output=True)
                subprocess.run(["openssl", "rsa", "-in", str(private), "-pubout",
                                "-out", str(cls.folder / (app + ".pub"))],
                               check=True, capture_output=True)
        return cls.folder / (name + (".pub" if public else ".pem"))


def signed_by(jwt, app):
    """True when the JWT's signature verifies with the named App's public key."""
    _, _, signing_input, signature = jwt_parts(jwt)
    work = Path(tempfile.mkdtemp(prefix="thimble-verify-"))
    try:
        (work / "data").write_bytes(signing_input)
        (work / "sig").write_bytes(signature)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(Keys.path(app, public=True)),
             "-signature", str(work / "sig"), str(work / "data")],
            capture_output=True)
        return result.returncode == 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


class Machine:
    """A synthetic home folder with stubbed curl and launchctl on PATH."""

    def __init__(self, test):
        self.tmp = Path(tempfile.mkdtemp(prefix="thimble-test-"))
        test.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.root = self.home / ".config" / "thimble"
        self.root.mkdir(parents=True)
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        for name, body in (("curl", STUB_CURL), ("launchctl", STUB_LAUNCHCTL)):
            stub = self.stubs / name
            stub.write_text(body)
            stub.chmod(0o755)
        self.curl_log = self.tmp / "curl.log"
        self.launchctl_log = self.tmp / "launchctl.log"

    def add_app(self, name, app_id, key=None, work_folder=None, group="agents",
                conf=None):
        """Creates an App folder with its key and app.conf. `conf` replaces the file."""
        folder = self.root / group / name
        folder.mkdir(parents=True)
        key_file = name + ".private-key.pem"
        if key is not None:
            shutil.copy(Keys.path(key), folder / key_file)
            (folder / key_file).chmod(0o600)
        if conf is None:
            conf = ("APP_ID=%s\nACCOUNT=%s\nKEY_FILE=%s\nWORK_FOLDER=%s\n"
                    % (app_id, ORG, key_file, work_folder or name.capitalize() + "Work"))
        (folder / "app.conf").write_text(conf)
        return folder

    def env(self, **extra):
        env = {
            "HOME": str(self.home),
            "PATH": str(self.stubs) + os.pathsep + os.environ["PATH"],
            "THIMBLE_NOW": str(NOW),
            "STUB_CURL_LOG": str(self.curl_log),
            "STUB_INSTALLATIONS": json.dumps(INSTALLATIONS),
            "STUB_LAUNCHCTL_LOG": str(self.launchctl_log),
            "TMPDIR": str(self.tmp),
        }
        env.update(extra)
        return env

    def run(self, *args, stdin="", **extra):
        return subprocess.run([str(a) for a in args], input=stdin, capture_output=True,
                              text=True, env=self.env(**extra), cwd=str(self.tmp))

    def curl_calls(self):
        if not self.curl_log.exists():
            return []
        return [json.loads(line) for line in self.curl_log.read_text().splitlines()]

    def token_requests(self):
        return [c for c in self.curl_calls() if "/access_tokens" in c["url"]]


def write_token(folder, text, age_seconds=0):
    token = folder / "token"
    token.write_text(text)
    token.chmod(0o600)
    os.utime(token, (NOW - age_seconds, NOW - age_seconds))
    return token


def output_lines(result):
    return [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]


# --- mint ------------------------------------------------------------------


class MintTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")

    def first_jwt(self):
        calls = self.machine.curl_calls()
        self.assertTrue(calls, "mint made no API call")
        return calls[0]["jwt"]

    def test_jwt_claims_carry_app_id_and_fixed_time_window(self):  # M1
        self.machine.run(THIMBLE, "mint", self.alpha)
        header, payload, _, _ = jwt_parts(self.first_jwt())
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(str(payload["iss"]), str(ALPHA_ID))
        self.assertEqual(payload["iat"], NOW - 60)
        self.assertEqual(payload["exp"], NOW + 540)

    def test_jwt_is_signed_with_this_apps_own_key(self):  # M2
        self.machine.run(THIMBLE, "mint", self.alpha)
        jwt = self.first_jwt()
        self.assertTrue(signed_by(jwt, "alpha"), "JWT does not verify with alpha's key")
        self.assertFalse(signed_by(jwt, "beta"), "JWT verifies with beta's key")

    def test_token_is_requested_for_the_installation_on_the_configured_account(self):  # M3
        self.machine.run(THIMBLE, "mint", self.alpha)
        requests = self.machine.token_requests()
        self.assertEqual(len(requests), 1, "expected one token request")
        self.assertEqual(requests[0]["method"], "POST")
        self.assertTrue(requests[0]["url"].endswith("/app/installations/222/access_tokens"),
                        requests[0]["url"])

    def test_mint_prints_only_the_token(self):  # M4
        result = self.machine.run(THIMBLE, "mint", self.alpha)
        self.assertEqual(result.stdout, "ghs_FAKE_%s_222\n" % ALPHA_ID)

    def test_mint_failure_prints_nothing_and_exits_non_zero(self):  # M5
        missing_key = self.machine.add_app("nokey", BETA_ID, key=None)
        not_installed = self.machine.add_app(
            "elsewhere", BETA_ID, key="beta",
            conf="APP_ID=%s\nACCOUNT=not-installed-anywhere\nKEY_FILE=elsewhere.private-key.pem\n"
                 "WORK_FOLDER=ElsewhereWork\n" % BETA_ID)
        cases = [
            ("key file missing", missing_key, {}),
            ("account not installed", not_installed, {}),
            ("API error with no token", self.alpha, {"STUB_CURL_FAIL": "access_tokens"}),
        ]
        for label, folder, extra in cases:
            with self.subTest(label):
                result = self.machine.run(THIMBLE, "mint", folder, **extra)
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertEqual(result.stdout, "", "stdout")


# --- refresh ---------------------------------------------------------------


class RefreshTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)

    def refresh(self):
        return self.machine.run(THIMBLE, "refresh")

    def assertToken(self, folder, expected):
        token = folder / "token"
        self.assertTrue(token.exists(), "%s has no token file" % folder.name)
        self.assertEqual(token.read_text().strip(), expected)

    def test_missing_token_is_minted_with_owner_only_mode(self):  # R1
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.refresh()
        self.assertToken(alpha, "ghs_FAKE_%s_222" % ALPHA_ID)
        self.assertEqual((alpha / "token").stat().st_mode & 0o777, 0o600)

    def test_token_is_replaced_only_from_40_minutes_old(self):  # R2
        for minutes, replaced in ((39, False), (40, True)):
            with self.subTest(minutes=minutes):
                machine = Machine(self)
                alpha = machine.add_app("alpha", ALPHA_ID, key="alpha")
                write_token(alpha, "ghs_OLD\n", age_seconds=minutes * 60)
                machine.run(THIMBLE, "refresh")
                if replaced:
                    self.assertEqual((alpha / "token").read_text().strip(),
                                     "ghs_FAKE_%s_222" % ALPHA_ID)
                else:
                    self.assertEqual((alpha / "token").read_text().strip(), "ghs_OLD")
                    self.assertEqual(machine.curl_calls(), [], "API called for a fresh token")

    def test_each_app_gets_its_own_token_signed_with_its_own_key(self):  # R3
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        # gamma has a key on disk but no KEY_FILE line: it must fail, not borrow beta's.
        gamma = self.machine.add_app(
            "gamma", GAMMA_ID, key="gamma",
            conf="APP_ID=%s\nACCOUNT=%s\nWORK_FOLDER=GammaWork\n" % (GAMMA_ID, ORG))
        self.refresh()
        self.assertToken(alpha, "ghs_FAKE_%s_222" % ALPHA_ID)
        self.assertToken(beta, "ghs_FAKE_%s_222" % BETA_ID)
        self.assertFalse((gamma / "token").exists(), "gamma got a token without a key")
        signers = {"%s" % ALPHA_ID: "alpha", "%s" % BETA_ID: "beta"}
        requests = self.machine.token_requests()
        self.assertEqual(len(requests), 2, "expected one token request per working App")
        for request in requests:
            app = signers[str(jwt_parts(request["jwt"])[1]["iss"])]
            self.assertTrue(signed_by(request["jwt"], app), "%s's JWT has the wrong key" % app)

    def test_failing_app_does_not_stop_the_others(self):  # R4
        alpha = self.machine.add_app("alpha", ALPHA_ID, key=None)  # key missing
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        write_token(alpha, "ghs_ALPHA_OLD\n", age_seconds=50 * 60)
        result = self.refresh()
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertToken(beta, "ghs_FAKE_%s_222" % BETA_ID)
        self.assertEqual((alpha / "token").read_text(), "ghs_ALPHA_OLD\n")

    def test_failure_leaves_no_temporary_file(self):  # R5
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        self.machine.run(THIMBLE, "refresh", STUB_CURL_FAIL="access_tokens")
        self.machine.run(THIMBLE, "refresh")  # the API is back: both get tokens
        self.assertToken(beta, "ghs_FAKE_%s_222" % BETA_ID)
        for folder in (alpha, beta):
            names = sorted(p.name for p in folder.iterdir())
            self.assertEqual(names, sorted(["app.conf", folder.name + ".private-key.pem",
                                            "token"]), folder.name)

    def test_log_has_one_line_per_app_and_no_token_text(self):  # R6
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.machine.add_app("beta", BETA_ID, key="beta")
        self.machine.add_app("gamma", GAMMA_ID, key=None)  # fails
        lines = output_lines(self.refresh())
        self.assertToken(alpha, "ghs_FAKE_%s_222" % ALPHA_ID)
        self.assertEqual(len(lines), 3, lines)
        for app in ("alpha", "beta", "gamma"):
            self.assertEqual(sum(app in line for line in lines), 1, (app, lines))
        self.assertFalse([line for line in lines if "ghs_" in line], "token text in the log")

    def test_only_folders_with_app_conf_are_apps(self):  # R7
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        retired = self.machine.root / "agents" / "retired"
        retired.mkdir()
        shutil.copy(Keys.path("beta"), retired / "retired.private-key.pem")
        (self.machine.root / "bin").mkdir()
        shutil.copy(THIMBLE, self.machine.root / "bin" / "thimble")
        (self.machine.root / "notes.txt").write_text("synthetic notes\n")
        (self.machine.root / "agents" / "notes.txt").write_text("synthetic notes\n")
        lines = output_lines(self.refresh())
        self.assertToken(alpha, "ghs_FAKE_%s_222" % ALPHA_ID)
        self.assertEqual(len(lines), 1, lines)
        self.assertFalse((retired / "token").exists())
        self.assertFalse((self.machine.root / "bin" / "token").exists())

    def test_app_conf_is_read_as_data_not_run(self):  # R8
        marks = [self.machine.tmp / ("pwned%d" % n) for n in (1, 2, 3)]
        self.machine.add_app(
            "evil", ALPHA_ID, key="alpha",
            conf="APP_ID=%s; touch %s\nACCOUNT=$(touch %s)\nKEY_FILE=evil.private-key.pem\n"
                 "WORK_FOLDER=Evil$(touch %s)Work\n" % (ALPHA_ID, marks[0], marks[1], marks[2]))
        lines = output_lines(self.refresh())
        block = self.machine.run(THIMBLE, "zshenv").stdout
        block_file = self.machine.tmp / "block.zsh"
        block_file.write_text(block)
        subprocess.run(["zsh", "-f", "-c", 'source "$1"', "_", str(block_file)],
                       env=self.machine.env(), cwd=str(self.machine.home), capture_output=True)
        self.assertTrue([line for line in lines if "evil" in line], "evil App not logged")
        for mark in marks:
            self.assertFalse(mark.exists(), "%s was created" % mark.name)


# --- git credential helper -------------------------------------------------


GIT_REQUEST = "protocol=https\nhost=github.com\n\n"
GIT_STORE = "protocol=https\nhost=github.com\nusername=someone\npassword=synthetic\n\n"


class HelperTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.beta = self.machine.add_app("beta", BETA_ID, key="beta")

    def helper(self, folder, operation, stdin=GIT_REQUEST):
        return self.machine.run(HELPER, folder, operation, stdin=stdin)

    def test_get_returns_the_named_apps_token(self):  # G1
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        write_token(self.beta, "ghs_SYNTHETIC_BETA\n")
        self.assertEqual(self.helper(self.alpha, "get").stdout,
                         "username=x-access-token\npassword=ghs_SYNTHETIC_ALPHA\n")
        self.assertEqual(self.helper(self.beta, "get").stdout,
                         "username=x-access-token\npassword=ghs_SYNTHETIC_BETA\n")

    def test_missing_or_empty_token_gives_no_output(self):  # G2
        token = write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        self.assertNotEqual(self.helper(self.alpha, "get").stdout, "", "present token")
        token.write_text("")
        self.assertEqual(self.helper(self.alpha, "get").stdout, "", "empty token")
        token.unlink()
        self.assertEqual(self.helper(self.alpha, "get").stdout, "", "missing token")

    def test_store_and_erase_change_nothing(self):  # G3
        token = write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n", age_seconds=600)
        for operation in ("store", "erase"):
            with self.subTest(operation):
                self.assertEqual(self.helper(self.alpha, operation, stdin=GIT_STORE).stdout, "")
        self.assertEqual(token.read_text(), "ghs_SYNTHETIC_ALPHA\n")
        self.assertEqual(int(token.stat().st_mtime), NOW - 600)
        self.assertEqual(self.helper(self.alpha, "get").stdout,
                         "username=x-access-token\npassword=ghs_SYNTHETIC_ALPHA\n")


# --- zshenv block ----------------------------------------------------------


class ZshenvTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        home = self.machine.home
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")
        self.beta = self.machine.add_app("beta", BETA_ID, key="beta", work_folder="BetaWork")
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        write_token(self.beta, "ghs_SYNTHETIC_BETA\n")
        for folder in ("AlphaWork/repo", "BetaWork/repo", "AlphaWorkOld", "Other"):
            (home / folder).mkdir(parents=True)
        (home / "Other" / "link").symlink_to(home / "AlphaWork" / "repo")
        result = self.machine.run(THIMBLE, "zshenv")
        self.block = self.machine.tmp / "block.zsh"
        self.block.write_text(result.stdout)

    def gh_token_in(self, folder, inherited=None):
        script = ('unset GH_TOKEN; [[ -n $INHERIT ]] && export GH_TOKEN=$INHERIT; '
                  'cd "$1" && source "$2"; print -r -- "${GH_TOKEN-<unset>}"')
        result = subprocess.run(
            ["zsh", "-f", "-c", script, "_", str(folder), str(self.block)],
            env=self.machine.env(INHERIT=inherited or ""), capture_output=True, text=True)
        return result.stdout.strip(), result.stderr

    def test_each_work_folder_gets_its_own_apps_token(self):  # Z1
        home = self.machine.home
        cases = [
            ("inside AlphaWork", home / "AlphaWork/repo", None, "ghs_SYNTHETIC_ALPHA"),
            ("AlphaWork itself", home / "AlphaWork", None, "ghs_SYNTHETIC_ALPHA"),
            ("lower-case path", Path(str(home) + "/alphawork/repo"), None, "ghs_SYNTHETIC_ALPHA"),
            ("symlink from outside", home / "Other/link", None, "ghs_SYNTHETIC_ALPHA"),
            ("inside BetaWork", home / "BetaWork/repo", None, "ghs_SYNTHETIC_BETA"),
            ("sibling AlphaWorkOld", home / "AlphaWorkOld", None, "<unset>"),
            ("outside", home / "Other", None, "<unset>"),
            ("outside keeps inherited", home / "Other", "gho_INHERITED", "gho_INHERITED"),
        ]
        for label, folder, inherited, expected in cases:
            with self.subTest(label):
                self.assertEqual(self.gh_token_in(folder, inherited)[0], expected)

    def test_unreadable_token_fails_closed_with_the_apps_placeholder(self):  # Z2
        token = self.alpha / "token"
        cases = [("missing", lambda: token.unlink()),
                 ("empty", lambda: token.write_text("")),
                 ("mode 000", lambda: token.chmod(0))]
        for label, damage in cases:
            with self.subTest(label):
                write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
                damage()
                value, stderr = self.gh_token_in(self.machine.home / "AlphaWork/repo",
                                                 inherited="gho_INHERITED")
                self.assertEqual(value, "alpha-token-unreadable")
                self.assertIn("alpha", stderr, "no warning naming the App")
                token.unlink(missing_ok=True)


# --- install ---------------------------------------------------------------


class InstallTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")
        self.bin = self.machine.root / "bin"
        self.plist = self.machine.home / "Library" / "LaunchAgents" / (LABEL + ".plist")

    def test_install_places_scripts_and_a_calendar_launchd_job(self):  # I1
        self.machine.run(INSTALL)
        for name in ("thimble", "git-credential-thimble"):
            installed = self.bin / name
            self.assertTrue(installed.exists(), "%s not installed" % name)
            self.assertTrue(os.access(installed, os.X_OK), "%s not executable" % name)
            self.assertEqual(installed.read_bytes(), (REPO / "bin" / name).read_bytes(), name)
        self.assertTrue(self.plist.exists(), "no plist")
        self.assertEqual(subprocess.run(["plutil", "-lint", str(self.plist)],
                                        capture_output=True).returncode, 0, "plist lint")
        job = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(job["Label"], LABEL)
        self.assertEqual(job["ProgramArguments"], [str(self.bin / "thimble"), "refresh"])
        self.assertIs(job["RunAtLoad"], True)
        self.assertEqual(job["StartCalendarInterval"], [{"Minute": m} for m in range(0, 60, 10)])
        self.assertNotIn("StartInterval", job)
        for key in ("StandardOutPath", "StandardErrorPath"):
            self.assertTrue(job[key].startswith(str(self.machine.home) + "/"), job[key])
        self.assertNotIn("~", self.plist.read_text())
        calls = self.machine.launchctl_log.read_text().splitlines()
        self.assertTrue(calls[0].startswith("bootout"), calls)
        self.assertEqual(calls[-1], "bootstrap gui/%d %s" % (os.getuid(), self.plist))

    def test_install_manages_one_zshenv_block_and_keeps_the_rest(self):  # I2
        zshenv = self.machine.home / ".zshenv"
        original = "export SYNTHETIC_SETTING=1\n# a line the founder wrote\n"
        zshenv.write_text(original)
        self.machine.run(INSTALL)
        first = zshenv.read_text()
        self.assertIn(original, first)
        self.assertEqual(first.count(BLOCK_START), 1, "start markers")
        self.assertEqual(first.count(BLOCK_END), 1, "end markers")
        self.assertIn("alphawork", first.lower())
        self.assertEqual((self.machine.home / ZSHENV_BACKUP).read_text(), original)
        self.machine.run(INSTALL)
        self.assertEqual(zshenv.read_text(), first, "second run changed .zshenv")


if __name__ == "__main__":
    unittest.main()
