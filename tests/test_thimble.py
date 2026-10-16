"""Tests for thimble (#2), run against synthetic Apps.

Run from the repository root:

    python3 -I tests/test_thimble.py

Nothing here touches a real App, the real HOME, launchd or the network. Keys are made
at test time with /usr/bin/openssl, GitHub's API is a stub `curl`, `launchctl` is a
stub, HOME is a temporary folder (an unresolved path, reached through a symlink such as
/var or /tmp), and the clock is fixed through THIMBLE_NOW. Every script runs in an
environment built from nothing: the developer's PATH is never used, so Homebrew tools
never run. No assertion depends on a generated key's value.

Platform assumptions: a case-insensitive file system (Z1's lower-case path) and a
non-root user (Z2's mode 000 token, R6+'s read-only App folder).
"""

import atexit
import base64
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
THIMBLE = REPO / "bin" / "thimble"
HELPER = REPO / "bin" / "git-credential-thimble"
INSTALL = REPO / "install"

OPENSSL = "/usr/bin/openssl"
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

NOW = 1_700_000_000
ORG = "Synthetic-Org"
# (installation ID, account login, account ID). The matching account (222) sits in the
# middle, a login that starts with ORG comes first, and none of these numbers, nor any
# App ID, equals another.
INSTALLATIONS = [(111, ORG + "-Labs", 9111), (222, ORG, 9222), (333, "another-org", 9333)]
MATCH_ID = 222
ALPHA_ID, BETA_ID, GAMMA_ID = 424242, 515151, 636363

LABEL = "com.asciizer0.thimble"
BLOCK_START = "# >>> thimble >>>"
BLOCK_END = "# <<< thimble <<<"
ZSHENV_BACKUP = ".zshenv.thimble-backup"

JWT_PATTERN = r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"


# --- Stubs on PATH ---------------------------------------------------------

STUB_CURL = r'''#!/usr/bin/python3 -I
# Stub for curl: records each call and answers like GitHub's App API.
# Secrets may only arrive through a header source (-H @- or -H @<path>). A call that puts
# one in an argument, or that reads a config file, is recorded as refused and exits 2.
import json, os, re, stat, sys
from base64 import urlsafe_b64decode
from urllib.parse import urlparse

INSTALLATIONS = json.loads('@INSTALLATIONS@')
args = sys.argv[1:]


def describe(info):
    if stat.S_ISFIFO(info.st_mode):
        kind = "pipe"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        kind = "other"
    return {"type": kind, "nlink": info.st_nlink}


try:
    stdin = describe(os.fstat(0))
except OSError:
    stdin = {"type": "closed", "nlink": 0}
call = {"args": args, "method": "GET", "url": "", "jwt": "", "header_source": None,
        "stdin": stdin, "refused": [],
        "first_arg_disables_config": bool(args) and args[0] in ("-q", "--disable")}


def finish(status):
    with open(os.environ["STUB_CURL_LOG"], "a") as log:
        log.write(json.dumps(call) + "\n")
    sys.exit(status)


for a in args:
    if "authorization" in a.lower() or "bearer" in a.lower():
        call["refused"].append("authorization text in an argument")
    if "eyJ" in a or "ghs_" in a:
        call["refused"].append("token text in an argument")
    if a in ("-K", "--config", "-u", "--user", "--oauth2-bearer") or (
            re.match(r"-[A-Za-z]*[Ku]", a) and not a.startswith("--")):
        call["refused"].append("option " + a)
if call["refused"]:
    finish(2)

headers = ""
for i, a in enumerate(args):
    nxt = args[i + 1] if i + 1 < len(args) else ""
    if a.startswith("https://"):
        call["url"] = a
    elif a in ("-X", "--request"):
        call["method"] = nxt
    elif a.startswith("-X") and len(a) > 2:
        call["method"] = a[2:]
    elif a in ("-d", "--data", "--data-raw", "--json"):
        call["method"] = "POST"
    elif a in ("-H", "--header"):
        if nxt == "@-":
            call["header_source"] = dict(describe(os.fstat(0)), form="stdin")
            headers += sys.stdin.read() + "\n"
        elif nxt.startswith("@"):
            try:
                call["header_source"] = dict(describe(os.stat(nxt[1:])), form="path")
                with open(nxt[1:]) as source:
                    headers += source.read() + "\n"
            except OSError as error:
                call["header_error"] = str(error)
                sys.stderr.write("curl: (26) Failed to open/read local data\n")
                finish(26)
        else:
            headers += nxt + "\n"
found = re.search(r"(?im)^authorization:[ \t]*bearer[ \t]+(\S+)[ \t]*$", headers)
call["jwt"] = found.group(1) if found else ""
fail_requested = any(a in ("-f", "--fail", "--fail-with-body") or
                     (re.fullmatch(r"-[A-Za-z]+", a) and "f" in a) for a in args)


def rejected(status, message):
    print(json.dumps({"message": message, "status": str(status)}))
    if fail_requested:
        sys.stderr.write("curl: (22) The requested URL returned error: %s STUB-CURL-STDERR\n" % status)
        finish(22)
    finish(0)


def issuer():
    try:
        payload = call["jwt"].split(".")[1]
        return json.loads(urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["iss"]
    except (IndexError, ValueError, KeyError):
        rejected(401, "A JSON web token could not be decoded")


path = urlparse(call["url"]).path
if not call["jwt"]:
    rejected(401, "Requires authentication")
iss = issuer()
if re.fullmatch(r"/app/installations/[0-9]+/access_tokens", path):
    if (os.environ.get("STUB_CURL_FAIL") == "access_tokens"
            or os.environ.get("STUB_CURL_FAIL_APP_ID") == str(iss)):
        rejected(401, "Bad credentials")
    print(json.dumps({"token": "ghs_FAKE_%s_%s" % (iss, path.split("/")[3]),
                      "expires_at": "2023-11-14T23:13:20Z", "marker": "RESPONSE-MARKER-2"}))
elif path == "/app/installations":
    print(json.dumps([{"id": number, "account": {"login": login, "id": account_id},
                       "app_id": iss, "marker": "RESPONSE-MARKER-1"}
                      for number, login, account_id in INSTALLATIONS]))
else:
    rejected(404, "Not Found")
finish(0)
'''.replace("@INSTALLATIONS@", json.dumps(INSTALLATIONS))

STUB_LAUNCHCTL = r'''#!/bin/bash -p
# Stub for launchctl: records its arguments, one call per line. `bootout` fails the way
# it does on a first install, when the job is not loaded yet.
printf '%s\n' "$*" >> "$STUB_LAUNCHCTL_LOG"
if [[ ${1:-} == bootout ]]; then
  echo "Boot-out failed: 3: No such process" >&2
  exit 3
fi
'''


# --- Builders and helpers --------------------------------------------------


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_parts(jwt):
    if jwt.count(".") != 2:
        raise AssertionError("not a JWT: %r" % jwt[:12])
    header, payload, signature = jwt.split(".")
    return (json.loads(b64url_decode(header)), json.loads(b64url_decode(payload)),
            (header + "." + payload).encode(), b64url_decode(signature))


def tool_env(home):
    """The environment for the helper tools the tests themselves run (openssl)."""
    return {"PATH": SYSTEM_PATH, "HOME": str(home)}


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
                subprocess.run([OPENSSL, "genrsa", "-out", str(private), "2048"],
                               check=True, capture_output=True, env=tool_env(cls.folder))
                first_line = private.read_text().splitlines()[0]
                if first_line != "-----BEGIN RSA PRIVATE KEY-----":
                    raise RuntimeError("expected a PKCS#1 key like GitHub's, got " + first_line)
                subprocess.run([OPENSSL, "rsa", "-in", str(private), "-pubout",
                                "-out", str(cls.folder / (app + ".pub"))],
                               check=True, capture_output=True, env=tool_env(cls.folder))
        return cls.folder / (name + (".pub" if public else ".pem"))


def signed_by(jwt, app):
    """True when the JWT's signature verifies with the named App's public key."""
    _, _, signing_input, signature = jwt_parts(jwt)
    work = Path(tempfile.mkdtemp(prefix="thimble-verify-"))
    try:
        (work / "data").write_bytes(signing_input)
        (work / "sig").write_bytes(signature)
        result = subprocess.run(
            [OPENSSL, "dgst", "-sha256", "-verify", str(Keys.path(app, public=True)),
             "-signature", str(work / "sig"), str(work / "data")],
            capture_output=True, env=tool_env(work))
        return result.returncode == 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def conf_lines(app_id=ALPHA_ID, account=ORG, key_file="alpha.private-key.pem",
               work_folder="AlphaWork"):
    return ["APP_ID=%s" % app_id, "ACCOUNT=%s" % account, "KEY_FILE=%s" % key_file,
            "WORK_FOLDER=%s" % work_folder]


def with_line(lines, key, new_line=None):
    """The lines with the one for `key` replaced by `new_line`, or removed if that is None."""
    result = []
    for line in lines:
        if line.split("=", 1)[0] != key:
            result.append(line)
        elif new_line is not None:
            result.append(new_line)
    return result


def conf_text(lines):
    return "".join(line + "\n" for line in lines)


def fake_token(app_id):
    """What the stub API hands out to this App for the matching installation."""
    return "ghs_FAKE_%s_%s" % (app_id, MATCH_ID)


def jwt_issuer(call):
    return str(jwt_parts(call["jwt"])[1]["iss"])


def mode_of(path):
    return stat.S_IMODE(path.stat().st_mode)


def listing(folder):
    return sorted(p.name for p in folder.iterdir())


def write_token(folder, text, age_seconds=0):
    token = folder / "token"
    token.write_text(text)
    token.chmod(0o600)
    os.utime(token, (NOW - age_seconds, NOW - age_seconds))
    return token


def output_lines(result):
    return [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]


class Machine:
    """A synthetic home folder, with stubbed curl and launchctl first on PATH."""

    def __init__(self, test, home_name="home"):
        self.tmp = Path(tempfile.mkdtemp(prefix="thimble-test-"))
        test.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / home_name
        self.root = self.home / ".config" / "thimble"
        self.root.mkdir(parents=True)
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        for name, body in (("curl", STUB_CURL), ("launchctl", STUB_LAUNCHCTL)):
            stub = self.stubs / name
            stub.write_text(body)
            stub.chmod(0o755)
        self.scratch = self.tmp / "tmp"  # the scripts' TMPDIR: an empty folder of its own
        self.scratch.mkdir()
        self.curl_log = self.tmp / "curl.log"
        self.launchctl_log = self.tmp / "launchctl.log"

    def add_app(self, name, app_id, key=None, work_folder=None, group="agents", conf=None):
        """Creates an App folder with its key and app.conf. `conf` replaces the file."""
        folder = self.root / group / name if group else self.root / name
        folder.mkdir(parents=True)
        key_file = name + ".private-key.pem"
        if key is not None:
            shutil.copy(Keys.path(key), folder / key_file)
            (folder / key_file).chmod(0o600)
        if conf is None:
            conf = conf_text(conf_lines(app_id, key_file=key_file,
                                        work_folder=work_folder or name.capitalize() + "Work"))
        (folder / "app.conf").write_text(conf)
        return folder

    def env(self, **extra):
        """The whole environment of a script: nothing is inherited from the developer."""
        env = {
            "HOME": str(self.home),
            "PATH": str(self.stubs) + os.pathsep + SYSTEM_PATH,
            "THIMBLE_NOW": str(NOW),
            "TMPDIR": str(self.scratch),
            "STUB_CURL_LOG": str(self.curl_log),
            "STUB_LAUNCHCTL_LOG": str(self.launchctl_log),
        }
        env.update(extra)
        return env

    def run(self, *args, stdin="", umask=None, cwd=None, unset=(), **env):
        """Runs a command in this machine's environment, plus `env`, minus `unset`."""
        environment = self.env(**env)
        for name in unset:
            environment.pop(name, None)
        return subprocess.run(
            [str(a) for a in args], input=stdin, capture_output=True, encoding="utf-8",
            errors="replace", env=environment, cwd=str(cwd or self.tmp),
            preexec_fn=(lambda: os.umask(umask)) if umask is not None else None)

    def gh_token_in(self, block, folder, inherited=None, **env):
        """What a child process sees as GH_TOKEN after zsh sources `block` in `folder`.

        Returns (value or "<unset>", stderr). Only an exported value counts. The tools
        are called by absolute path, so this works with an empty PATH too.
        """
        script = ('unset GH_TOKEN; [[ -n $INHERIT ]] && export GH_TOKEN=$INHERIT; '
                  'cd "$1" && source "$2"; /usr/bin/printenv GH_TOKEN || print -r -- "<unset>"')
        result = subprocess.run(
            ["/bin/zsh", "-f", "-c", script, "_", str(folder), str(block)],
            env=self.env(INHERIT=inherited or "", **env), capture_output=True,
            encoding="utf-8", errors="replace")
        return result.stdout.strip(), result.stderr

    def curl_calls(self):
        if not self.curl_log.exists():
            return []
        return [json.loads(line) for line in self.curl_log.read_text().splitlines()]

    def token_requests(self):
        return [c for c in self.curl_calls() if "/access_tokens" in c["url"]]

    def launchctl_calls(self):
        if not self.launchctl_log.exists():
            return []
        return self.launchctl_log.read_text().splitlines()


# --- mint ------------------------------------------------------------------


class MintTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")

    def mint(self, folder=None, **env):
        return self.machine.run(THIMBLE, "mint", folder or self.alpha, **env)

    def first_call(self):
        calls = self.machine.curl_calls()
        self.assertTrue(calls, "mint made no API call")
        return calls[0]

    def test_m1_jwt_carries_app_id_and_fixed_time_window(self):
        result = self.mint()
        self.assertEqual(result.returncode, 0, result.stderr)
        first = self.first_call()
        self.assertEqual((first["method"], urlparse(first["url"]).path),
                         ("GET", "/app/installations"), "first API call")
        self.assertTrue(re.fullmatch(JWT_PATTERN, first["jwt"]),
                        "the JWT is not base64url: " + first["jwt"][:12])
        header, payload, _, _ = jwt_parts(first["jwt"])
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(str(payload["iss"]), str(ALPHA_ID))
        self.assertEqual(payload["iat"], NOW - 60)
        self.assertEqual(payload["exp"], NOW + 540)

    def test_m2_jwt_is_signed_with_this_apps_own_key(self):
        result = self.mint()
        self.assertEqual(result.returncode, 0, result.stderr)
        jwt = self.first_call()["jwt"]
        self.assertTrue(signed_by(jwt, "alpha"), "JWT does not verify with alpha's key")
        self.assertFalse(signed_by(jwt, "beta"), "JWT verifies with beta's key")

    def test_m3_token_is_requested_for_the_installation_on_the_configured_account(self):
        result = self.mint()
        self.assertEqual(result.returncode, 0, result.stderr)
        requests = self.machine.token_requests()
        self.assertEqual(len(requests), 1, "expected one token request")
        self.assertEqual(requests[0]["method"], "POST")
        self.assertEqual(urlparse(requests[0]["url"]).path,
                         "/app/installations/%d/access_tokens" % MATCH_ID)

    def test_m4_mint_prints_only_the_token(self):
        result = self.mint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, fake_token(ALPHA_ID) + "\n")

    def test_m5_any_failure_prints_nothing_and_exits_non_zero(self):
        missing_key = self.machine.add_app("nokey", BETA_ID, key=None)
        not_installed = self.machine.add_app(
            "elsewhere", BETA_ID, key="beta",
            conf=conf_text(conf_lines(BETA_ID, account="not-installed-anywhere",
                                      key_file="elsewhere.private-key.pem",
                                      work_folder="ElsewhereWork")))
        cases = [
            ("key file missing", missing_key, {}),
            ("account not installed", not_installed, {}),
            ("API error with no token", self.alpha, {"STUB_CURL_FAIL": "access_tokens"}),
        ]
        for label, folder, env in cases:
            with self.subTest(label):
                result = self.mint(folder, **env)
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertEqual(result.stdout, "", "stdout")


# --- refresh ---------------------------------------------------------------


class RefreshTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)

    def refresh(self, **kwargs):
        return self.machine.run(THIMBLE, "refresh", **kwargs)

    def assertToken(self, folder, expected):
        token = folder / "token"
        self.assertTrue(token.exists(), "%s has no token file" % folder.name)
        self.assertEqual(token.read_text().strip(), expected)

    def test_r1_missing_token_is_minted_with_owner_only_mode(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        result = self.refresh(umask=0o022)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertEqual(mode_of(alpha / "token"), 0o600)

    def test_r2_token_is_replaced_once_it_is_2400_seconds_old(self):
        for age, replaced in ((2399, False), (2400, True)):
            with self.subTest(age=age):
                machine = Machine(self)
                alpha = machine.add_app("alpha", ALPHA_ID, key="alpha")
                token = write_token(alpha, "ghs_OLD\n", age_seconds=age)
                inode = token.stat().st_ino
                result = machine.run(THIMBLE, "refresh", umask=0o022)
                self.assertEqual(result.returncode, 0, result.stderr)
                if replaced:
                    self.assertToken(alpha, fake_token(ALPHA_ID))
                    self.assertNotEqual(token.stat().st_ino, inode, "overwritten in place")
                    self.assertEqual(mode_of(token), 0o600)
                else:
                    self.assertEqual(token.read_text(), "ghs_OLD\n")
                    self.assertEqual(machine.curl_calls(), [], "API called for a fresh token")

    def test_r3_each_app_gets_its_own_token_signed_with_its_own_key(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        # gamma has a key on disk but no KEY_FILE line: it must fail, not borrow beta's.
        gamma = self.machine.add_app(
            "gamma", GAMMA_ID, key="gamma",
            conf=conf_text(with_line(conf_lines(GAMMA_ID, work_folder="GammaWork"), "KEY_FILE")))
        self.refresh()
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertToken(beta, fake_token(BETA_ID))
        self.assertFalse((gamma / "token").exists(), "gamma got a token without a key")
        signers = {str(ALPHA_ID): "alpha", str(BETA_ID): "beta"}
        requests = self.machine.token_requests()
        self.assertEqual(len(requests), 2, "expected one token request per working App")
        for request in requests:
            app = signers[jwt_issuer(request)]
            self.assertTrue(signed_by(request["jwt"], app), "%s's JWT has the wrong key" % app)

    def test_r4_failing_app_does_not_stop_the_others(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key=None)  # key missing
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        write_token(alpha, "ghs_ALPHA_OLD\n", age_seconds=50 * 60)
        result = self.refresh()
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertToken(beta, fake_token(BETA_ID))
        self.assertEqual((alpha / "token").read_text(), "ghs_ALPHA_OLD\n")

    def test_r4_plus_api_failure_keeps_the_old_token(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        write_token(alpha, "ghs_ALPHA_OLD\n", age_seconds=50 * 60)
        result = self.refresh(STUB_CURL_FAIL_APP_ID=str(ALPHA_ID))
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertToken(beta, fake_token(BETA_ID))
        self.assertEqual((alpha / "token").read_bytes(), b"ghs_ALPHA_OLD\n")

    def test_r5_failure_leaves_no_temporary_file(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        self.refresh(STUB_CURL_FAIL="access_tokens")
        asked = {jwt_issuer(c) for c in self.machine.token_requests()}
        self.assertEqual(asked, {str(ALPHA_ID), str(BETA_ID)}, "the run did not ask for both")
        for folder in (alpha, beta):
            self.assertEqual(listing(folder), ["app.conf", folder.name + ".private-key.pem"])
        result = self.refresh()  # the API is back: both get tokens
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertToken(beta, fake_token(BETA_ID))
        for folder in (alpha, beta):
            self.assertEqual(listing(folder),
                             ["app.conf", folder.name + ".private-key.pem", "token"])

    def test_r6_log_has_one_line_per_app_and_no_token_text(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.machine.add_app("beta", BETA_ID, key="beta")
        self.machine.add_app("gamma", GAMMA_ID, key=None)  # fails
        lines = output_lines(self.refresh())
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertEqual(len(lines), 3, lines)
        for app in ("alpha", "beta", "gamma"):
            self.assertEqual(sum(app in line for line in lines), 1, (app, lines))
        self.assertFalse([line for line in lines if "ghs_" in line], "token text in the log")

    def test_r6_plus_each_line_shows_the_result_and_no_curl_text_or_jwt(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.machine.add_app("beta", BETA_ID, key="beta")
        gamma = self.machine.add_app("gamma", GAMMA_ID, key="gamma")
        gamma.chmod(0o500)  # a new token cannot be written here
        self.addCleanup(gamma.chmod, 0o700)
        lines = output_lines(self.refresh(STUB_CURL_FAIL_APP_ID=str(BETA_ID)))
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertEqual(len(lines), 3, lines)
        for app, expected in (("alpha", r"alpha: ok$"), ("beta", r"beta: failed: \S"),
                              ("gamma", r"gamma: failed: \S")):
            named = [line for line in lines if re.search(r"\b%s\b" % app, line)]
            self.assertEqual(len(named), 1, (app, lines))
            self.assertRegex(named[0], r"^" + expected)
        for line in lines:
            for text in ("ghs_", "eyJ", "STUB-CURL-STDERR"):
                self.assertNotIn(text, line)

    def test_r7_apps_are_the_folders_one_or_two_levels_down_that_hold_an_app_conf(self):
        root = self.machine.root
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")  # agents/alpha
        solo = self.machine.add_app("solo", BETA_ID, key="beta", group=None)  # one level down
        deep = self.machine.add_app("nested", GAMMA_ID, key="gamma",
                                    group="agents/deep")  # three levels down
        retired = [root / "retired", root / "agents" / "retired"]
        for folder in retired:
            folder.mkdir()
            shutil.copy(Keys.path("beta"), folder / "retired.private-key.pem")
        (root / "bin").mkdir()
        shutil.copy(THIMBLE, root / "bin" / "thimble")
        (root / "notes.txt").write_text("synthetic notes\n")
        (root / "agents" / "notes.txt").write_text("synthetic notes\n")
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertToken(solo, fake_token(BETA_ID))
        lines = output_lines(result)
        self.assertEqual(len(lines), 2, lines)
        for folder in retired + [root / "bin", deep]:
            self.assertFalse((folder / "token").exists(), "%s got a token" % folder.name)
        asked = {jwt_issuer(c) for c in self.machine.curl_calls()}
        self.assertEqual(asked, {str(ALPHA_ID), str(BETA_ID)}, "API calls for other folders")

    def test_r8_app_conf_is_read_as_data_and_never_run(self):
        hostile = [  # (field to replace, the hostile line, extra lines after the valid ones)
            ("APP_ID", "APP_ID=%s; touch ran-1" % ALPHA_ID, []),
            ("APP_ID", "APP_ID=`touch ran-2`", []),
            ("ACCOUNT", "ACCOUNT=$(touch ran-3)", []),
            ("ACCOUNT", 'ACCOUNT=x"+__import__("os").system("touch ran-4")+"', []),
            ("ACCOUNT", "ACCOUNT=x'+__import__('os').system('touch ran-5')+'", []),
            ("KEY_FILE", "KEY_FILE=$(touch ran-6)", []),
            ("WORK_FOLDER", "WORK_FOLDER=Odd'; touch ran-7; 'Work", []),
            ("WORK_FOLDER", 'WORK_FOLDER=Odd"$(touch ran-8)"Work', []),
            ("WORK_FOLDER", "WORK_FOLDER=Odd\\", [";touch ran-9"]),  # ends in a backslash
            (None, None, ["touch ran-10"]),
        ]
        names = []
        work_folders = [self.machine.home]
        for number, (field, line, extra) in enumerate(hostile, 1):
            name = "evil%d" % number
            lines = conf_lines(ALPHA_ID, key_file=name + ".private-key.pem",
                               work_folder=name + "Work")
            if field:
                lines = with_line(lines, field, line)
            lines += extra
            self.machine.add_app(name, ALPHA_ID, key="alpha", conf=conf_text(lines))
            value = [l for l in lines if l.startswith("WORK_FOLDER=")][0].split("=", 1)[1]
            work_folders.append(self.machine.home / value)
            work_folders[-1].mkdir(parents=True, exist_ok=True)
            names.append(name)
        lines = output_lines(self.refresh())
        for name in names:
            named = [line for line in lines if re.search(r"\b%s\b" % name, line)]
            self.assertEqual(len(named), 1, (name, lines))
            self.assertIn("failed", named[0])
        block = self.machine.tmp / "block.zsh"
        block.write_text(self.machine.run(THIMBLE, "zshenv").stdout)
        for folder in work_folders:  # the block is sourced in HOME and in each work folder
            self.machine.gh_token_in(block, folder)
        made = sorted(p.name for p in self.machine.tmp.rglob("ran-*"))
        self.assertEqual(made, [], "app.conf text was run")


# --- git credential helper -------------------------------------------------


GIT_REQUEST = "protocol=https\nhost=github.com\n\n"
GIT_STORE = "protocol=https\nhost=github.com\nusername=someone\npassword=synthetic\n\n"


def git_reply(token):
    return "username=x-access-token\npassword=%s\n" % token


def snapshot(folder):
    """Path, size, mtime, mode of everything under `folder`."""
    seen = {}
    for where, folders, files in os.walk(folder):
        for name in folders + files:
            path = os.path.join(where, name)
            info = os.lstat(path)
            seen[path] = (info.st_size, info.st_mtime_ns, stat.S_IMODE(info.st_mode))
    return seen


class HelperTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.beta = self.machine.add_app("beta", BETA_ID, key="beta")

    def helper(self, folder, operation, stdin=GIT_REQUEST):
        return self.machine.run(HELPER, folder, operation, stdin=stdin)

    def test_g1_get_returns_the_named_apps_token(self):
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        write_token(self.beta, "ghs_SYNTHETIC_BETA\n")
        for folder, token in ((self.alpha, "ghs_SYNTHETIC_ALPHA"), (self.beta, "ghs_SYNTHETIC_BETA")):
            with self.subTest(folder.name):
                result = self.helper(folder, "get")
                self.assertEqual(result.stdout, git_reply(token))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_g2_missing_or_empty_token_gives_no_output(self):
        token = write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        present = self.helper(self.alpha, "get")
        self.assertEqual(present.stdout, git_reply("ghs_SYNTHETIC_ALPHA"), "present token")
        self.assertEqual(present.returncode, 0, present.stderr)
        token.write_text("")
        self.assertEqual(self.helper(self.alpha, "get").stdout, "", "empty token")
        token.unlink()
        self.assertEqual(self.helper(self.alpha, "get").stdout, "", "missing token")

    def test_g3_store_and_erase_change_nothing(self):
        token = write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n", age_seconds=600)
        for operation in ("store", "erase"):
            with self.subTest(operation):
                result = self.helper(self.alpha, operation, stdin=GIT_STORE)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(token.read_text(), "ghs_SYNTHETIC_ALPHA\n")
        self.assertEqual(int(token.stat().st_mtime), NOW - 600)
        self.assertEqual(self.helper(self.alpha, "get").stdout, git_reply("ghs_SYNTHETIC_ALPHA"))

    def test_g3_plus_store_and_erase_write_nothing_anywhere(self):
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n", age_seconds=600)
        # A helper that does nothing at all must not pass: first check that it answers.
        answer = self.helper(self.alpha, "get")
        self.assertEqual(answer.stdout, git_reply("ghs_SYNTHETIC_ALPHA"), "get answers")
        before = snapshot(self.machine.home)
        for operation in ("store", "erase"):
            result = self.helper(self.alpha, operation, stdin=GIT_STORE)
            self.assertEqual(result.returncode, 0, "%s: %s" % (operation, result.stderr))
        self.assertEqual(snapshot(self.machine.home), before, "files under HOME changed")
        for where, _, files in os.walk(self.machine.home):
            for name in files:
                path = os.path.join(where, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    with open(path, "rb") as data:
                        self.assertNotIn(b"synthetic", data.read(), path)


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
        self.assertEqual(result.returncode, 0, result.stderr)
        self.block = self.machine.tmp / "block.zsh"
        self.block.write_text(result.stdout)

    def gh_token_in(self, folder, inherited=None):
        return self.machine.gh_token_in(self.block, folder, inherited)

    def test_z1_each_work_folder_gets_its_own_apps_token_exported(self):
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
            ("inside replaces inherited", home / "AlphaWork/repo", "gho_INHERITED",
             "ghs_SYNTHETIC_ALPHA"),
        ]
        for label, folder, inherited, expected in cases:
            with self.subTest(label):
                self.assertEqual(self.gh_token_in(folder, inherited)[0], expected)

    def test_z2_unreadable_token_fails_closed_with_the_apps_placeholder(self):
        token = self.alpha / "token"
        damages = [("missing", lambda: token.unlink()),
                   ("empty", lambda: token.write_text("")),
                   ("mode 000", lambda: token.chmod(0))]
        for label, damage in damages:
            for inherited in (None, "gho_INHERITED"):
                with self.subTest(label, inherited=inherited):
                    token.unlink(missing_ok=True)
                    write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
                    damage()
                    value, stderr = self.gh_token_in(self.machine.home / "AlphaWork/repo",
                                                     inherited=inherited)
                    self.assertEqual(value, "alpha-token-unreadable")
                    warnings = [line for line in stderr.splitlines()
                                if line.startswith("thimble: ") and "alpha" in line]
                    self.assertTrue(warnings, "no warning of the block's own naming alpha: " + stderr)


class ZshenvQuotingTests(unittest.TestCase):

    def test_z4_the_block_quotes_every_path_it_contains(self):
        machine = Machine(self, home_name="home 'q' \"d\" $(touch ran-h1) `touch ran-h2` \\b")
        alpha = machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")
        write_token(alpha, "ghs_SYNTHETIC_ALPHA\n")
        for folder in ("AlphaWork/repo", "Other"):
            (machine.home / folder).mkdir(parents=True)
        result = machine.run(THIMBLE, "zshenv")
        self.assertEqual(result.returncode, 0, result.stderr)
        block = machine.tmp / "block.zsh"
        block.write_text(result.stdout)
        self.assertEqual(machine.gh_token_in(block, machine.home / "AlphaWork/repo")[0],
                         "ghs_SYNTHETIC_ALPHA")
        self.assertEqual(machine.gh_token_in(block, machine.home / "Other")[0], "<unset>")
        made = sorted(p.name for p in machine.tmp.rglob("ran-h*"))
        self.assertEqual(made, [], "a path in the block was run")




# --- install ---------------------------------------------------------------


class InstallTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")
        self.bin = self.machine.root / "bin"
        self.zshenv = self.machine.home / ".zshenv"
        self.plist = self.machine.home / "Library" / "LaunchAgents" / (LABEL + ".plist")

    def test_i1_install_places_scripts_and_a_calendar_launchd_job(self):
        # The stub launchctl fails `bootout` with exit 3, as on a first install.
        result = self.machine.run(INSTALL)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("thimble", "git-credential-thimble"):
            installed = self.bin / name
            self.assertTrue(installed.exists(), "%s not installed" % name)
            self.assertTrue(os.access(installed, os.X_OK), "%s not executable" % name)
            self.assertEqual(installed.read_bytes(), (REPO / "bin" / name).read_bytes(), name)
        self.assertTrue(self.plist.exists(), "no plist")
        self.assertEqual(subprocess.run(["/usr/bin/plutil", "-lint", str(self.plist)],
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
        self.assertEqual(self.machine.launchctl_calls(),
                         ["bootout gui/%d/%s" % (os.getuid(), LABEL),
                          "bootstrap gui/%d %s" % (os.getuid(), self.plist)])

    def test_i2_install_manages_one_zshenv_block_and_keeps_the_rest(self):
        before_block = "export SYNTHETIC_SETTING=1\n# a line the founder wrote\n"
        after_block = "alias synthetic-alias=true\nexport SYNTHETIC_LAST=1\n"
        old_block = (BLOCK_START + "\n# left by an earlier version\nexport OLD_THING=1\n"
                     + BLOCK_END + "\n")
        seed = before_block + old_block + after_block
        self.zshenv.write_text(seed)
        backup = self.machine.home / ZSHENV_BACKUP

        def read(path):
            self.assertTrue(path.exists(), "%s was not written" % path.name)
            return path.read_text()

        def block_of(text):
            return text.partition(BLOCK_START)[2].partition(BLOCK_END)[0].lower()

        def assert_shape(text):
            self.assertEqual(text.count(BLOCK_START), 1, "start markers")
            self.assertEqual(text.count(BLOCK_END), 1, "end markers")
            self.assertEqual(text.partition(BLOCK_START)[0], before_block)
            self.assertEqual(text.partition(BLOCK_END)[2], "\n" + after_block)

        result = self.machine.run(INSTALL)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = read(self.zshenv)
        assert_shape(first)
        self.assertIn("alphawork", block_of(first))
        self.assertEqual(read(backup), seed)

        self.machine.add_app("beta", BETA_ID, key="beta", work_folder="BetaWork")
        result = self.machine.run(INSTALL)
        self.assertEqual(result.returncode, 0, result.stderr)
        second = read(self.zshenv)
        assert_shape(second)
        self.assertIn("alphawork", block_of(second))
        self.assertIn("betawork", block_of(second))
        self.assertEqual(read(backup), first)

        # A third run changes nothing, and does not even rewrite the files.
        for path in (self.zshenv, backup):
            os.utime(path, ns=(1_600_000_000 * 10**9, 1_600_000_000 * 10**9))
        stamps = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in (self.zshenv, backup)}
        result = self.machine.run(INSTALL)
        self.assertEqual(result.returncode, 0, result.stderr)
        for path, stamp in stamps.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), stamp, path.name)


if __name__ == "__main__":
    unittest.main()
