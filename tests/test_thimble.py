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
import hashlib
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

# C3: App folders whose name breaks the rules, as (group folder, name).
INVALID_FOLDERS = [("agents", "bad name"), ("agents", "bad'name"), ("agents", ".hidden"),
                   ("agents", "-dash"), ("bad group", "alpha2")]


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
    elif a in ("-H", "--header") or (a.startswith("-H") and len(a) > 2):
        value = nxt if a in ("-H", "--header") else a[2:]
        if value == "@-":
            call["header_source"] = dict(describe(os.fstat(0)), form="stdin")
            headers += sys.stdin.read() + "\n"
        elif value.startswith("@"):
            try:
                call["header_source"] = dict(describe(os.stat(value[1:])), form="path")
                with open(value[1:]) as source:
                    headers += source.read() + "\n"
            except OSError as error:
                call["header_error"] = str(error)
                sys.stderr.write("curl: (26) Failed to open/read local data\n")
                finish(26)
        else:
            headers += value + "\n"
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

# S1 and S2: stands in for every system tool except the two stubs. It logs the tool's
# name, its arguments, and what its stdin is, then runs the real tool.
RECORDER = r'''#!/usr/bin/python3 -I
import json, os, stat, sys

name = os.path.basename(sys.argv[0])
try:
    info = os.fstat(0)
    kind = "pipe" if stat.S_ISFIFO(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
    stdin = {"type": kind, "nlink": info.st_nlink}
except OSError:
    stdin = {"type": "closed", "nlink": 0}
line = json.dumps({"name": name, "args": sys.argv[1:], "stdin": stdin}) + "\n"
log = os.open(os.environ["STUB_WRAPPER_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
os.write(log, line.encode())
os.close(log)
for folder in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
    real = os.path.join(folder, name)
    if os.path.isfile(real) and os.access(real, os.X_OK):
        os.execv(real, [name] + sys.argv[1:])
sys.stderr.write("%s: command not found\n" % name)
sys.exit(127)
'''

# E4: an openssl that a script would find first if it looked one up by name.
DECOY_OPENSSL = '''#!/bin/bash -p
/usr/bin/touch ran-openssl
exit 1
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


class Recorder:
    """A folder of links to RECORDER, one under each tool name in the system folders."""

    folder = None

    @classmethod
    def path(cls):
        if cls.folder is None:
            cls.folder = Path(tempfile.mkdtemp(prefix="thimble-recorder-"))
            atexit.register(shutil.rmtree, cls.folder, True)
            script = cls.folder / "recorder"
            script.write_text(RECORDER)
            script.chmod(0o755)
            names = set()
            for system_folder in SYSTEM_PATH.split(":"):
                for entry in os.scandir(system_folder):
                    try:
                        runnable = entry.is_file() and os.access(entry.path, os.X_OK)
                    except OSError:  # a link into a place this user may not look at
                        runnable = False
                    if runnable:
                        names.add(entry.name)
            for name in names - {"curl", "launchctl", "recorder"}:
                os.symlink(script, cls.folder / name)
        return cls.folder


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


KEYS_FOLDER = "@KEYS@"  # stands for the keys folder of whichever machine uses the text


def invalid_confs():
    """Every invalid app.conf of C1, as (label, text, KEY_FILE value or None).

    Each case changes one line of a valid file, or one thing about the whole file.
    """
    valid = conf_lines()
    field_values = [
        ("APP_ID", ["", "42424a", "0424242", "424242 ", '"424242"']),
        ("ACCOUNT", ["", "Synthetic_Org", "-Synthetic-Org", "Synthetic-Org-", "a" * 40,
                     '"Synthetic-Org"']),
        ("KEY_FILE", ["../keys/alpha.private-key.pem", KEYS_FOLDER + "/alpha.private-key.pem",
                      ".alpha.private-key.pem", "sub/alpha.private-key.pem", "alpha key.pem"]),
        ("WORK_FOLDER", ["", "/AlphaWork", "~/AlphaWork", "../AlphaWork", "AlphaWork/..",
                         "./AlphaWork", "AlphaWork/", "Alpha//Work", "Alpha Work",
                         "Alpha*Work", ".AlphaWork", "AlphäWork"]),
    ]
    cases = []
    for field, values in field_values:
        for value in values:
            text = conf_text(with_line(valid, field, "%s=%s" % (field, value)))
            cases.append(("%s=%r" % (field, value), text, value if field == "KEY_FILE" else None))
    whole_file = [
        ("unknown key EXTRA=1", conf_text(valid + ["EXTRA=1"])),
        ("app_id= instead of APP_ID=", conf_text(with_line(valid, "APP_ID", "app_id=%s" % ALPHA_ID))),
        ("APP_ID twice, same value", conf_text(valid + ["APP_ID=%s" % ALPHA_ID])),
        ("APP_ID twice, different values", conf_text(valid + ["APP_ID=%s" % BETA_ID])),
        ("ACCOUNT missing", conf_text(with_line(valid, "ACCOUNT"))),
        ("WORK_FOLDER missing", conf_text(with_line(valid, "WORK_FOLDER"))),
        ("export APP_ID=...", conf_text(with_line(valid, "APP_ID", "export APP_ID=%s" % ALPHA_ID))),
        ("APP_ID = ...", conf_text(with_line(valid, "APP_ID", "APP_ID = %s" % ALPHA_ID))),
        ("a line starting with spaces",
         conf_text(with_line(valid, "KEY_FILE", "  KEY_FILE=alpha.private-key.pem"))),
        ("a line without =", conf_text(valid + ["synthetic text without an equals sign"])),
        ("CRLF line endings", "".join(line + "\r\n" for line in valid)),
    ]
    cases.extend((label, text, None) for label, text in whole_file)
    return cases


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
        self.keys = self.root / "keys"
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
        self.recorder_log = self.tmp / "recorder.log"

    def add_key(self, key, key_file, root=None):
        """Copies a synthetic key to <root>/keys/<key_file> (keys folder 700, key 600)."""
        folder = (root or self.root) / "keys"
        folder.mkdir(parents=True, exist_ok=True)
        folder.chmod(0o700)
        target = folder / key_file
        shutil.copy(Keys.path(key), target)
        target.chmod(0o600)
        return target

    def add_app(self, name, app_id, key=None, work_folder=None, group="agents", conf=None,
                root=None, key_file=None):
        """Creates an App folder with an app.conf, and its key in <root>/keys.

        The folder is <root>/<group>/<name>, or <root>/<name> when group is None. `conf`
        replaces the generated app.conf. The key is left out when `key` is None.
        """
        root = root or self.root
        folder = root / group / name if group else root / name
        folder.mkdir(parents=True)
        key_file = key_file or name + ".private-key.pem"
        if key is not None:
            self.add_key(key, key_file, root)
        if conf is None:
            conf = conf_text(conf_lines(app_id, key_file=key_file,
                                        work_folder=work_folder or name.capitalize() + "Work"))
        (folder / "app.conf").write_bytes(conf.encode("utf-8"))
        return folder

    def place_named_key(self, app_folder, key_file):
        """Makes the file that a KEY_FILE value names exist, holding alpha's key.

        It is created wherever a script could look for it: in the keys folder, in the
        App folder, or at the absolute path the value gives.
        """
        for base in (self.keys, app_folder):
            target = Path(os.path.normpath(os.path.join(str(base), key_file)))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(Keys.path("alpha"), target)

    def env(self, **extra):
        """The whole environment of a script: nothing is inherited from the developer."""
        env = {
            "HOME": str(self.home),
            "PATH": str(self.stubs) + os.pathsep + SYSTEM_PATH,
            "THIMBLE_NOW": str(NOW),
            "TMPDIR": str(self.scratch),
            "STUB_CURL_LOG": str(self.curl_log),
            "STUB_LAUNCHCTL_LOG": str(self.launchctl_log),
            "STUB_WRAPPER_LOG": str(self.recorder_log),
        }
        env.update(extra)
        return env

    def recording_path(self):
        """A PATH that puts the recording wrapper ahead of the system folders."""
        return os.pathsep.join([str(self.stubs), str(Recorder.path()), SYSTEM_PATH])

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

    def recorded_commands(self):
        """Every command the recording wrapper saw: name, args, stdin type and link count."""
        if not self.recorder_log.exists():
            return []
        return [json.loads(line) for line in self.recorder_log.read_text().splitlines()]

    def git_env(self):
        """What the install tests add so that no global or outer git setting applies."""
        return {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CEILING_DIRECTORIES": str(self.tmp)}

    def git(self, repo, *args, **env):
        who = {"NAME": "Synthetic Author", "EMAIL": "author@example.invalid",
               "DATE": "2023-11-14T22:13:20+00:00"}
        for role in ("AUTHOR", "COMMITTER"):
            for field, value in who.items():
                env.setdefault("GIT_%s_%s" % (role, field), value)
        return self.run("/usr/bin/git", "-C", repo, *args, **dict(self.git_env(), **env))

    def make_checkout(self, name="checkout", add=None, append=None):
        """A temporary git repository with committed copies of install and bin/.

        `add` maps extra paths to the text of files to commit with them, and `append`
        maps committed paths to text added to the copy before it is committed.
        """
        repo = self.tmp / name
        shutil.copytree(REPO / "bin", repo / "bin")
        shutil.copy2(INSTALL, repo / "install")
        for relative, text in (add or {}).items():
            (repo / relative).write_text(text)
        for relative, text in (append or {}).items():
            with open(repo / relative, "a") as script:
                script.write(text)
        for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "Synthetic checkout")):
            result = self.git(repo, *args)
            if result.returncode != 0:
                raise RuntimeError("git %s failed: %s" % (args[0], result.stderr))
        return repo


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

    def test_m6_key_file_is_read_only_from_the_keys_folder_of_the_root(self):
        with self.subTest("a: the keys folder wins over a key in the App folder"):
            machine = Machine(self)
            alpha = machine.add_app("alpha", ALPHA_ID, key="alpha")
            shutil.copy(Keys.path("beta"), alpha / "alpha.private-key.pem")
            result = machine.run(THIMBLE, "mint", alpha)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = machine.curl_calls()
            self.assertTrue(calls, "mint made no API call")
            jwt = calls[0]["jwt"]
            self.assertTrue(signed_by(jwt, "alpha"), "not signed with the keys folder's key")
            self.assertFalse(signed_by(jwt, "beta"), "signed with the App folder's key")
        with self.subTest("b: a key only in the App folder is not used"):
            machine = Machine(self)
            alpha = machine.add_app("alpha", ALPHA_ID, key=None)
            shutil.copy(Keys.path("alpha"), alpha / "alpha.private-key.pem")
            result = machine.run(THIMBLE, "mint", alpha)
            self.assertNotEqual(result.returncode, 0, "exit status")
            self.assertEqual(result.stdout, "", "stdout")
            self.assertEqual(machine.curl_calls(), [], "an API call was made")
        with self.subTest("c: the root argument names the keys folder"):
            machine = Machine(self)
            alpha = machine.add_app("alpha", ALPHA_ID, key="beta")  # the default root holds beta's
            other_root = machine.home / "other-root"
            machine.add_key("alpha", "alpha.private-key.pem", root=other_root)
            result = machine.run(THIMBLE, "mint", alpha, other_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = machine.curl_calls()
            self.assertTrue(calls, "mint made no API call")
            jwt = calls[0]["jwt"]
            self.assertTrue(signed_by(jwt, "alpha"), "not signed with the other root's key")
            self.assertFalse(signed_by(jwt, "beta"), "signed with the default root's key")


# --- refresh ---------------------------------------------------------------


class TokenTestCase(unittest.TestCase):
    """Base for the tests that read the token files that refresh writes."""

    def assertToken(self, folder, expected):
        token = folder / "token"
        self.assertTrue(token.exists(), "%s has no token file" % folder.name)
        self.assertEqual(token.read_text().strip(), expected)


class RefreshTests(TokenTestCase):

    def setUp(self):
        self.machine = Machine(self)

    def refresh(self, *args, **kwargs):
        return self.machine.run(THIMBLE, "refresh", *args, **kwargs)

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
        # gamma has a key in the keys folder but no KEY_FILE line: it must fail, not borrow beta's.
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
            self.assertEqual(listing(folder), ["app.conf"])
        result = self.refresh()  # the API is back: both get tokens
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertToken(beta, fake_token(BETA_ID))
        for folder in (alpha, beta):
            self.assertEqual(listing(folder), ["app.conf", "token"])

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
            conf = conf_lines(ALPHA_ID, key_file=name + ".private-key.pem",
                              work_folder=name + "Work")
            if field:
                conf = with_line(conf, field, line)
            conf += extra
            self.machine.add_app(name, ALPHA_ID, key="alpha", conf=conf_text(conf))
            value = [entry for entry in conf if entry.startswith("WORK_FOLDER=")][0].split("=", 1)[1]
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

    def test_r9_the_keys_and_bin_folders_are_never_apps(self):
        root, home = self.machine.root, self.machine.home
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.machine.add_key("beta", "beta.private-key.pem")
        # Otherwise valid confs: only their place makes them not Apps.
        for folder, work in ((root / "keys", "KeysWork"), (root / "keys" / "extra", "KeysWork"),
                             (root / "bin", "BinWork")):
            folder.mkdir(exist_ok=True)
            (folder / "app.conf").write_text(conf_text(
                conf_lines(BETA_ID, key_file="beta.private-key.pem", work_folder=work)))
        shutil.copy(THIMBLE, root / "bin" / "thimble")
        for folder in ("AlphaWork", "KeysWork", "BinWork"):
            (home / folder).mkdir()
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(alpha, fake_token(ALPHA_ID))
        self.assertEqual(len(output_lines(result)), 1, output_lines(result))
        self.assertEqual(sorted(str(p) for p in root.rglob("token")), [str(alpha / "token")])
        block = self.machine.run(THIMBLE, "zshenv")
        self.assertEqual(block.returncode, 0, block.stderr)
        block_file = self.machine.tmp / "block.zsh"
        block_file.write_text(block.stdout)
        self.assertEqual(self.machine.gh_token_in(block_file, home / "AlphaWork")[0],
                         fake_token(ALPHA_ID), "control")
        for work in ("KeysWork", "BinWork"):
            self.assertEqual(self.machine.gh_token_in(block_file, home / work)[0], "<unset>", work)

    def test_r10_an_app_with_an_invalid_app_conf_fails_on_its_own(self):
        conf = conf_text(with_line(conf_lines(), "ACCOUNT", 'ACCOUNT="%s"' % ORG))
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha", conf=conf)
        beta = self.machine.add_app("beta", BETA_ID, key="beta")
        write_token(alpha, "ghs_ALPHA_OLD\n", age_seconds=50 * 60)
        result = self.refresh()
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertToken(beta, fake_token(BETA_ID))
        named = [line for line in output_lines(result) if re.search(r"\balpha\b", line)]
        self.assertEqual(len(named), 1, named)
        self.assertRegex(named[0], r"^alpha: failed: ")
        self.assertRegex(named[0].lower(), r"invalid.*app\.conf|app\.conf.*invalid")
        self.assertEqual((alpha / "token").read_bytes(), b"ghs_ALPHA_OLD\n")
        self.assertNotIn(str(ALPHA_ID), {jwt_issuer(c) for c in self.machine.curl_calls()})

    def test_r11_refresh_works_on_the_root_it_is_given_with_that_roots_keys(self):
        alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        write_token(alpha, "ghs_ALPHA_OLD\n", age_seconds=50 * 60)
        # The default root's keys folder holds gamma's key under beta's KEY_FILE name.
        self.machine.add_key("gamma", "beta.private-key.pem")
        other_root = self.machine.home / "other-root"
        beta = self.machine.add_app("beta", BETA_ID, key="beta", root=other_root)
        result = self.refresh(other_root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertToken(beta, fake_token(BETA_ID))
        requests = self.machine.token_requests()
        self.assertEqual(len(requests), 1, "expected one token request")
        self.assertTrue(signed_by(requests[0]["jwt"], "beta"), "not signed with beta's own key")
        self.assertFalse(signed_by(requests[0]["jwt"], "gamma"), "signed with the default root's key")
        self.assertEqual((alpha / "token").read_bytes(), b"ghs_ALPHA_OLD\n")
        self.assertNotIn(str(ALPHA_ID), {jwt_issuer(c) for c in self.machine.curl_calls()})


# --- app.conf validation -----------------------------------------------------


class ConfTests(TokenTestCase):

    def test_c1_every_invalid_app_conf_is_refused_before_any_api_call(self):
        for label, text, key_file in invalid_confs():
            with self.subTest(label):
                machine = Machine(self)
                alpha = machine.add_app("alpha", ALPHA_ID, key="alpha",
                                        conf=text.replace(KEYS_FOLDER, str(machine.keys)))
                if key_file is not None:  # only validation may stop mint, not a missing file
                    machine.place_named_key(alpha, key_file.replace(KEYS_FOLDER, str(machine.keys)))
                result = machine.run(THIMBLE, "mint", alpha)
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertEqual(result.stdout, "", "stdout")
                self.assertEqual(machine.curl_calls(), [], "an API call was made")

    def test_c2_valid_app_confs_are_accepted(self):
        valid = conf_lines()
        key_file = "alpha_2026-10.private-key.pem"
        cases = [  # (label, app.conf text, KEY_FILE value, WORK_FOLDER value)
            ("comments and blank lines",
             conf_text(["# a synthetic comment", ""] + valid[:2] + ["", "# another"] + valid[2:]),
             "alpha.private-key.pem", "AlphaWork"),
            ("keys in another order", conf_text([valid[3], valid[1], valid[2], valid[0]]),
             "alpha.private-key.pem", "AlphaWork"),
            ("no newline after the last line (ACCOUNT)",
             conf_text([valid[0], valid[2], valid[3], valid[1]]).rstrip("\n"),
             "alpha.private-key.pem", "AlphaWork"),
            ("KEY_FILE with digits, dots and hyphens",
             conf_text(with_line(valid, "KEY_FILE", "KEY_FILE=" + key_file)),
             key_file, "AlphaWork"),
            ("WORK_FOLDER with three names",
             conf_text(with_line(valid, "WORK_FOLDER", "WORK_FOLDER=Work/Agents/Alpha-1.x")),
             "alpha.private-key.pem", "Work/Agents/Alpha-1.x"),
        ]
        for label, text, key_file, work_folder in cases:
            with self.subTest(label):
                machine = Machine(self)
                alpha = machine.add_app("alpha", ALPHA_ID, key="alpha", key_file=key_file, conf=text)
                minted = machine.run(THIMBLE, "mint", alpha)
                self.assertEqual(minted.returncode, 0, minted.stderr)
                self.assertEqual(minted.stdout, fake_token(ALPHA_ID) + "\n")
                write_token(alpha, "ghs_SYNTHETIC_ALPHA\n")
                (machine.home / work_folder).mkdir(parents=True)
                block = machine.run(THIMBLE, "zshenv")
                self.assertEqual(block.returncode, 0, block.stderr)
                block_file = machine.tmp / "block.zsh"
                block_file.write_text(block.stdout)
                self.assertEqual(machine.gh_token_in(block_file, machine.home / work_folder)[0],
                                 "ghs_SYNTHETIC_ALPHA")

    def test_c3_an_invalid_app_folder_name_fails_like_an_invalid_app_conf(self):
        machine = Machine(self)
        alpha = machine.add_app("alpha", ALPHA_ID, key="alpha")
        invalid = [machine.add_app(name, BETA_ID, key="beta", group=group,
                                   key_file="beta.private-key.pem", work_folder="BadWork")
                   for group, name in INVALID_FOLDERS]
        result = machine.run(THIMBLE, "refresh")
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertToken(alpha, fake_token(ALPHA_ID))
        lines = output_lines(result)
        self.assertEqual(len(lines), 6, lines)
        for folder in invalid:
            named = [line for line in lines if folder.name in line]
            self.assertEqual(len(named), 1, (folder.name, lines))
            self.assertIn("failed", named[0])
            self.assertFalse((folder / "token").exists(), "%s got a token" % folder.name)
        self.assertEqual({jwt_issuer(c) for c in machine.token_requests()}, {str(ALPHA_ID)})


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
        for folder, token in ((self.alpha, "ghs_SYNTHETIC_ALPHA"),
                              (self.beta, "ghs_SYNTHETIC_BETA")):
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

    def test_g4_get_answers_only_for_https_and_github_com(self):
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        answered = [
            ("https and github.com", "protocol=https\nhost=github.com\n\n"),
            ("host in capitals", "protocol=https\nhost=GitHub.COM\n\n"),
            ("protocol in capitals", "protocol=HTTPS\nhost=github.com\n\n"),
            ("host line before protocol line", "host=github.com\nprotocol=https\n\n"),
            ("extra lines", "protocol=https\nhost=github.com\npath=synthetic/repo.git\n"
                            "capability[]=authtype\nwwwauth[]=Basic realm=\"GitHub\"\n\n"),
        ]
        ignored = [
            ("another host", "protocol=https\nhost=example.com\n\n"),
            ("a subdomain", "protocol=https\nhost=gist.github.com\n\n"),
            ("github.com as a prefix", "protocol=https\nhost=github.com.example.net\n\n"),
            ("github.com as a suffix", "protocol=https\nhost=notgithub.com\n\n"),
            ("port 443", "protocol=https\nhost=github.com:443\n\n"),
            ("port 8443", "protocol=https\nhost=github.com:8443\n\n"),
            ("http", "protocol=http\nhost=github.com\n\n"),
            ("no protocol line", "host=github.com\n\n"),
            ("no host line", "protocol=https\n\n"),
            ("github.com only in the path",
             "protocol=https\nhost=example.com\npath=github.com/synthetic/repo.git\n\n"),
            ("empty input", ""),
        ]
        for label, request in answered:
            with self.subTest("answers: " + label):
                result = self.helper(self.alpha, "get", stdin=request)
                self.assertEqual(result.stdout, git_reply("ghs_SYNTHETIC_ALPHA"))
                self.assertEqual(result.returncode, 0, result.stderr)
        for label, request in ignored:
            with self.subTest("ignores: " + label):
                self.assertEqual(self.helper(self.alpha, "get", stdin=request).stdout, "")

    def test_g5_the_token_file_must_be_exactly_one_line(self):
        token = self.alpha / "token"
        for label, content in (("two tokens", b"ghs_A\nghs_B\n"),
                               ("a trailing blank line", b"ghs_A\n\n"),
                               ("a leading blank line", b"\nghs_A\n"),
                               ("only a newline", b"\n")):
            with self.subTest(label):
                token.write_bytes(content)
                self.assertEqual(self.helper(self.alpha, "get").stdout, "")
        token.write_bytes(b"ghs_A")  # the final newline is optional
        result = self.helper(self.alpha, "get")
        self.assertEqual(result.stdout, git_reply("ghs_A"))
        self.assertEqual(result.returncode, 0, result.stderr)


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


class ZshenvInvalidAppTests(unittest.TestCase):

    def test_z3_any_invalid_app_makes_zshenv_fail_as_a_whole(self):
        for label, text, _ in invalid_confs():
            with self.subTest(label):
                machine = Machine(self)
                machine.add_app("alpha", ALPHA_ID, key="alpha")
                machine.add_app("broken", BETA_ID, key="beta",
                                conf=text.replace(KEYS_FOLDER, str(machine.keys)))
                result = machine.run(THIMBLE, "zshenv")
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertEqual(result.stdout, "", "stdout")
                self.assertIn("broken", result.stderr, "stderr does not name the App's folder")
        for group, name in INVALID_FOLDERS:
            with self.subTest("folder %s/%s" % (group, name)):
                machine = Machine(self)
                machine.add_app("alpha", ALPHA_ID, key="alpha")
                machine.add_app(name, BETA_ID, key="beta", group=group,
                                key_file="beta.private-key.pem", work_folder="BadWork")
                result = machine.run(THIMBLE, "zshenv")
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertEqual(result.stdout, "", "stdout")
                self.assertIn(name, result.stderr, "stderr does not name the App's folder")


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


OLD_BLOCK = BLOCK_START + "\n# left by an earlier version\nexport OLD_THING=1\n" + BLOCK_END + "\n"


def install_footprint(machine):
    """What an install leaves behind: scripts, plist, launchctl calls, .zshenv and its backup."""
    zshenv = machine.home / ".zshenv"
    return {
        "scripts folder": (machine.root / "bin").exists(),
        "plist": (machine.home / "Library" / "LaunchAgents" / (LABEL + ".plist")).exists(),
        "launchctl calls": machine.launchctl_calls(),
        ".zshenv": zshenv.read_bytes() if zshenv.exists() else None,
        "backup": (machine.home / ZSHENV_BACKUP).exists(),
    }


class InstallTests(unittest.TestCase):
    """Every install test runs `install` from a temporary git repository."""

    def prepare(self, **checkout):
        machine = Machine(self)
        machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")
        return machine, machine.make_checkout(**checkout)

    def install(self, machine, script, cwd=None):
        return machine.run(script, cwd=cwd, **machine.git_env())

    def test_i1_install_places_scripts_and_a_calendar_launchd_job(self):
        machine, checkout = self.prepare()
        bin_folder = machine.root / "bin"
        plist = machine.home / "Library" / "LaunchAgents" / (LABEL + ".plist")
        # The stub launchctl fails `bootout` with exit 3, as on a first install.
        result = self.install(machine, checkout / "install")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("thimble", "git-credential-thimble"):
            installed = bin_folder / name
            self.assertTrue(installed.exists(), "%s not installed" % name)
            self.assertTrue(os.access(installed, os.X_OK), "%s not executable" % name)
            self.assertEqual(installed.read_bytes(), (checkout / "bin" / name).read_bytes(), name)
        self.assertTrue(plist.exists(), "no plist")
        self.assertEqual(subprocess.run(["/usr/bin/plutil", "-lint", str(plist)],
                                        capture_output=True, env=tool_env(machine.home)).returncode,
                         0, "plist lint")
        job = plistlib.loads(plist.read_bytes())
        self.assertEqual(job["Label"], LABEL)
        self.assertEqual(job["ProgramArguments"], [str(bin_folder / "thimble"), "refresh"])
        self.assertIs(job["RunAtLoad"], True)
        self.assertEqual(job["StartCalendarInterval"], [{"Minute": m} for m in range(0, 60, 10)])
        self.assertNotIn("StartInterval", job)
        for key in ("StandardOutPath", "StandardErrorPath"):
            self.assertTrue(job[key].startswith(str(machine.home) + "/"), job[key])
        self.assertNotIn("~", plist.read_text())
        self.assertEqual(job["EnvironmentVariables"], {"PATH": SYSTEM_PATH})
        self.assertEqual(machine.launchctl_calls(),
                         ["bootout gui/%d/%s" % (os.getuid(), LABEL),
                          "bootstrap gui/%d %s" % (os.getuid(), plist)])

    def test_i2_install_manages_one_zshenv_block_and_keeps_the_rest(self):
        machine, checkout = self.prepare()
        zshenv = machine.home / ".zshenv"
        backup = machine.home / ZSHENV_BACKUP
        before_block = "export SYNTHETIC_SETTING=1\n# a line the founder wrote\n"
        after_block = "alias synthetic-alias=true\nexport SYNTHETIC_LAST=1\n"
        seed = before_block + OLD_BLOCK + after_block
        zshenv.write_text(seed)

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

        result = self.install(machine, checkout / "install")
        self.assertEqual(result.returncode, 0, result.stderr)
        first = read(zshenv)
        assert_shape(first)
        self.assertIn("alphawork", block_of(first))
        self.assertEqual(read(backup), seed)

        machine.add_app("beta", BETA_ID, key="beta", work_folder="BetaWork")
        result = self.install(machine, checkout / "install")
        self.assertEqual(result.returncode, 0, result.stderr)
        second = read(zshenv)
        assert_shape(second)
        self.assertIn("alphawork", block_of(second))
        self.assertIn("betawork", block_of(second))
        self.assertEqual(read(backup), first)

        # A third run changes nothing, and does not even rewrite the files.
        for path in (zshenv, backup):
            os.utime(path, ns=(1_600_000_000 * 10**9, 1_600_000_000 * 10**9))
        stamps = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (zshenv, backup)}
        result = self.install(machine, checkout / "install")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path, stamp in stamps.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), stamp, path.name)

    def test_i3_install_refuses_code_that_is_not_committed_and_changes_nothing(self):
        def edit(relative):
            def apply(machine, repo):
                with open(repo / relative, "a") as script:
                    script.write("\n# an edit\n")
            return apply

        def stage_edit(machine, repo):
            edit("bin/thimble")(machine, repo)
            self.assertEqual(machine.git(repo, "add", "bin/thimble").returncode, 0)

        def create(relative):
            def apply(machine, repo):
                (repo / relative).write_text("synthetic\n")
            return apply

        def remove_git_folder(machine, repo):
            shutil.rmtree(repo / ".git")

        cases = [  # (label, change to the checkout, text that stderr must contain)
            ("bin/thimble edited", edit("bin/thimble"), "bin/thimble"),
            ("an edit staged but not committed", stage_edit, "bin/thimble"),
            ("untracked bin/extra", create("bin/extra"), "bin/extra"),
            ("untracked notes.txt at the root", create("notes.txt"), "notes.txt"),
            ("install itself edited", edit("install"), "install"),
            ("a copy with no .git", remove_git_folder, "git"),
        ]
        for label, change, named in cases:
            with self.subTest(label):
                machine, repo = self.prepare()
                (machine.home / ".zshenv").write_text("export SYNTHETIC_SETTING=1\n" + OLD_BLOCK)
                change(machine, repo)
                before = install_footprint(machine)
                result = self.install(machine, repo / "install")
                self.assertNotEqual(result.returncode, 0, "exit status")
                self.assertIn(named, result.stderr.lower(), "stderr")
                self.assertEqual(install_footprint(machine), before, "install changed something")
        with self.subTest("control: a file that .gitignore lists does not block"):
            machine, repo = self.prepare(add={".gitignore": "ignored.txt\n"})
            (repo / "ignored.txt").write_text("synthetic\n")
            result = self.install(machine, repo / "install")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((machine.root / "bin" / "thimble").exists(), "scripts not installed")

    def test_i4_install_reports_what_it_installed_and_installs_from_its_own_checkout(self):
        machine, repo = self.prepare()
        other = machine.make_checkout("other", append={"bin/thimble": "\n# a different copy\n"})
        result = self.install(machine, repo / "install", cwd=other)
        self.assertEqual(result.returncode, 0, result.stderr)
        head = machine.git(repo, "rev-parse", "HEAD").stdout.strip()
        self.assertRegex(head, r"^[0-9a-f]{40}$")
        lines = result.stdout.splitlines()
        installed_files = {}
        for name in ("thimble", "git-credential-thimble"):
            installed = machine.root / "bin" / name
            self.assertTrue(installed.exists(), "%s not installed" % name)
            committed = machine.git(repo, "show", "HEAD:bin/" + name).stdout
            self.assertEqual(installed.read_text(), committed, name)
            installed_files[name] = installed
        self.assertNotEqual(installed_files["thimble"].read_bytes(),
                            (other / "bin" / "thimble").read_bytes(), "installed the other checkout")
        self.assertIn("commit " + head, lines)
        for installed in installed_files.values():
            digest = hashlib.sha256(installed.read_bytes()).hexdigest()
            self.assertIn("%s  %s" % (digest, installed), lines)

    def test_i5_an_invalid_app_makes_install_change_nothing(self):
        machine, checkout = self.prepare()
        conf = conf_text(with_line(conf_lines(GAMMA_ID, key_file="gamma.private-key.pem",
                                              work_folder="GammaWork"),
                                   "ACCOUNT", 'ACCOUNT="%s"' % ORG))
        machine.add_app("gamma", GAMMA_ID, key="gamma", conf=conf)
        (machine.home / ".zshenv").write_text("export SYNTHETIC_SETTING=1\n" + OLD_BLOCK)
        before = install_footprint(machine)
        result = self.install(machine, checkout / "install")
        self.assertNotEqual(result.returncode, 0, "exit status")
        self.assertIn("gamma", result.stderr, "stderr")
        self.assertEqual(install_footprint(machine), before, "install changed something")


# --- secrets stay out of arguments and temp files ---------------------------


class SecretsTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha")
        self.beta = self.machine.add_app("beta", BETA_ID, key="beta")

    def mint_then_refresh(self):
        """Runs mint for alpha, then refresh for alpha and beta, behind the recording wrapper."""
        path = self.machine.recording_path()
        minted = self.machine.run(THIMBLE, "mint", self.alpha, PATH=path)
        refreshed = self.machine.run(THIMBLE, "refresh", PATH=path)
        return minted, refreshed

    def test_s1_no_secret_appears_in_any_process_arguments(self):
        minted, refreshed = self.mint_then_refresh()
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(refreshed.returncode, 0, refreshed.stderr)
        calls = self.machine.curl_calls()
        self.assertEqual([c["refused"] for c in calls if c["refused"]], [], "curl refused a call")
        self.assertEqual(len(self.machine.token_requests()), 3, "the curl calls were not recorded")
        secrets = {"RESPONSE-MARKER-1", "RESPONSE-MARKER-2",
                   fake_token(ALPHA_ID), fake_token(BETA_ID)}
        for call in calls:
            if call["jwt"].count(".") == 2:
                secrets.update([call["jwt"], call["jwt"].split(".")[2]])  # the JWT and its signature
        for key in ("alpha", "beta"):
            secrets.update(line for line in Keys.path(key).read_text().splitlines()[1:-1] if line)
        commands = [("curl", c["args"]) for c in calls]
        commands += [(r["name"], r["args"]) for r in self.machine.recorded_commands()]
        for name, args in commands:
            for arg in args:
                for secret in secrets:
                    if secret in arg:
                        self.fail("%s was given a secret in its arguments" % name)

    def test_s2_secrets_reach_other_processes_through_pipes(self):
        minted, refreshed = self.mint_then_refresh()
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(refreshed.returncode, 0, refreshed.stderr)
        calls = self.machine.curl_calls()
        self.assertEqual([c["refused"] for c in calls if c["refused"]], [], "curl refused a call")
        self.assertEqual(len(self.machine.token_requests()), 3, "the curl calls were not recorded")
        for call in calls:
            self.assertIsNotNone(call["header_source"], "a curl call without a header source")
            self.assertEqual(call["header_source"]["type"], "pipe", call["url"])
        for command in calls + self.machine.recorded_commands():
            stdin = command["stdin"]
            self.assertFalse(stdin["type"] == "file" and stdin["nlink"] == 0,
                             "%s read stdin from a deleted file" % command.get("name", "curl"))

    def test_s3_the_scripts_use_no_here_documents(self):
        # A static check: the recording wrapper cannot see a builtin such as `read`.
        for script in (THIMBLE, HELPER):
            with self.subTest(script.name):
                self.assertNotIn("<<", script.read_text())


# --- independence from the caller's environment -----------------------------


class EnvironmentTests(unittest.TestCase):

    def setUp(self):
        self.machine = Machine(self)
        self.alpha = self.machine.add_app("alpha", ALPHA_ID, key="alpha", work_folder="AlphaWork")

    def markers(self):
        return sorted(p.name for p in self.machine.tmp.rglob("ran-*"))

    def test_e1_python_never_loads_modules_from_the_working_folder_or_pythonpath(self):
        work, plant = self.machine.tmp / "work", self.machine.tmp / "plant"
        for folder in (work, plant):
            folder.mkdir()
            for module in ("json", "base64"):
                (folder / (module + ".py")).write_text('open("ran-%s", "w").close()\n' % module)
        minted = self.machine.run(THIMBLE, "mint", self.alpha, cwd=work, PYTHONPATH=str(plant))
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(minted.stdout, fake_token(ALPHA_ID) + "\n")
        refreshed = self.machine.run(THIMBLE, "refresh", cwd=work, PYTHONPATH=str(plant))
        self.assertEqual(refreshed.returncode, 0, refreshed.stderr)
        self.assertEqual((self.alpha / "token").read_text().strip(), fake_token(ALPHA_ID))
        self.assertEqual(self.markers(), [], "a planted module was loaded")

    def test_e2_bash_startup_settings_from_the_environment_are_ignored(self):
        write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        for name in ("bash-env", "env"):
            (self.machine.tmp / name).write_text("/usr/bin/touch ran-%s\n" % name)
        env = {"BASH_ENV": str(self.machine.tmp / "bash-env"), "ENV": str(self.machine.tmp / "env"),
               "SHELLOPTS": "xtrace"}
        for name in ("curl", "cat", "printf", "read"):
            body = "() { /usr/bin/touch ran-function-%s; }" % name
            env[name] = body  # how bash 3.2 exports a function
            env["BASH_FUNC_%s%%%%" % name] = body  # how newer bash versions do
        minted = self.machine.run(THIMBLE, "mint", self.alpha, **env)
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(minted.stdout, fake_token(ALPHA_ID) + "\n")
        answer = self.machine.run(HELPER, self.alpha, "get", stdin=GIT_REQUEST, **env)
        self.assertEqual(answer.returncode, 0, answer.stderr)
        self.assertEqual(answer.stdout, git_reply("ghs_SYNTHETIC_ALPHA"))
        self.assertEqual(self.markers(), [], "bash ran code from the environment")
        for text in ("eyJ", "ghs_"):
            self.assertNotIn(text, minted.stderr + answer.stderr, "secret text on stderr")

    def test_e3_curl_config_files_are_never_read(self):
        (self.machine.home / ".curlrc").write_text("silent\nproxy = http://127.0.0.1:9\n")
        minted = self.machine.run(THIMBLE, "mint", self.alpha)
        refreshed = self.machine.run(THIMBLE, "refresh")
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(refreshed.returncode, 0, refreshed.stderr)
        self.assertEqual(len(self.machine.token_requests()), 2, "the curl calls were not recorded")
        for call in self.machine.curl_calls():
            self.assertTrue(call["first_arg_disables_config"],
                            "-q or --disable is not the first argument: %s" % call["args"])

    def test_e4_mint_uses_usr_bin_openssl(self):
        decoy = self.machine.stubs / "openssl"
        decoy.write_text(DECOY_OPENSSL)
        decoy.chmod(0o755)
        minted = self.machine.run(THIMBLE, "mint", self.alpha)
        self.assertEqual(minted.returncode, 0, minted.stderr)
        self.assertEqual(minted.stdout, fake_token(ALPHA_ID) + "\n")
        self.assertEqual(self.markers(), [], "the openssl found on PATH was run")

    def test_e5_the_helper_and_the_zshenv_block_run_no_external_command(self):
        home = self.machine.home
        (home / "AlphaWork" / "repo").mkdir(parents=True)
        token = write_token(self.alpha, "ghs_SYNTHETIC_ALPHA\n")
        block = self.machine.run(THIMBLE, "zshenv")
        self.assertEqual(block.returncode, 0, block.stderr)
        block_file = self.machine.tmp / "block.zsh"
        block_file.write_text(block.stdout)
        empty_path = self.machine.tmp / "empty-path"
        empty_path.mkdir()
        answer = self.machine.run(HELPER, self.alpha, "get", stdin=GIT_REQUEST, PATH=str(empty_path))
        self.assertEqual(answer.stdout, git_reply("ghs_SYNTHETIC_ALPHA"))
        self.assertEqual(answer.returncode, 0, answer.stderr)
        in_work = home / "AlphaWork" / "repo"
        self.assertEqual(self.machine.gh_token_in(block_file, in_work, PATH=str(empty_path))[0],
                         "ghs_SYNTHETIC_ALPHA")
        token.unlink()
        self.assertEqual(self.machine.gh_token_in(block_file, in_work, PATH=str(empty_path))[0],
                         "alpha-token-unreadable")


if __name__ == "__main__":
    unittest.main()
