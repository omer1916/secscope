"""Positive / negative cases for every Python AST rule (SPEC §12 "kural-başı test")."""

from __future__ import annotations

from pathlib import Path

import pytest

from secscope.analysis.python_checks import check_python
from secscope.analysis.source import SourceFile

# rule_id -> list of (positive snippet, negative snippet)
CASES: dict[str, list[tuple[str, str]]] = {
    "SAST-SQLI-001": [
        (
            "def v():\n    q = request.args.get('q')\n    cur.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n",
            "def v():\n    q = request.args.get('q')\n    cur.execute('SELECT * FROM t WHERE n = ?', (q,))\n",
        ),
        (
            "def v(name):\n    cur.execute(f'SELECT * FROM users WHERE name = {name}')\n",
            "def v():\n    cur.execute('SELECT 1')\n",
        ),
    ],
    "SAST-CMDI-001": [
        (
            "def v():\n    h = request.args['h']\n    os.system('ping ' + h)\n",
            "def v():\n    subprocess.run(['ping', '-c', '1', host])\n",
        ),
        (
            "subprocess.run('ls ' + d, shell=True)\n",
            "subprocess.run('ls -la', shell=True)\n",
        ),
    ],
    "SAST-EVAL-001": [("def v():\n    eval(request.args['e'])\n", "eval('1 + 1')\n")],
    "SAST-SSTI-001": [
        (
            "def v():\n    return render_template_string(request.args['t'])\n",
            "render_template_string('<p>{{ x }}</p>', x=1)\n",
        )
    ],
    "SAST-DESER-001": [
        ("data = pickle.loads(blob)\n", "data = json.loads(blob)\n"),
        ("cfg = yaml.load(text)\n", "cfg = yaml.load(text, Loader=yaml.SafeLoader)\n"),
    ],
    "SAST-PATH-001": [
        (
            "def v():\n    p = os.path.join(BASE, request.args['f'])\n    return open(p).read()\n",
            "def v():\n    return send_from_directory(BASE, request.args['f'])\n",
        )
    ],
    "SAST-REDIRECT-001": [
        (
            "def v():\n    return redirect(request.args.get('next'))\n",
            "def v():\n    return redirect(url_for('index'))\n",
        )
    ],
    "SAST-SSRF-001": [
        (
            "def v():\n    return requests.get(request.args['url']).text\n",
            "def v():\n    return requests.get('https://api.example.com').text\n",
        )
    ],
    "SAST-XSS-003": [
        ("def v(x):\n    return Markup(x)\n", "def v():\n    return Markup('<b>static</b>')\n")
    ],
    "SAST-XSS-004": [
        (
            "def v():\n    n = request.args.get('n')\n    return f'<h1>Hello {n}</h1>'\n",
            "def v():\n    n = request.args.get('n')\n    return f'<h1>Hello {escape(n)}</h1>'\n",
        ),
        (
            "@app.route('/u/<name>')\ndef v(name):\n    return '<p>' + name + '</p>'\n",
            "def v():\n    rows = conn.execute('SELECT n FROM t WHERE q = ?', (request.args['q'],)).fetchall()\n    return f'<p>{rows[0][0]}</p>'\n",
        ),
    ],
    "SAST-DEBUG-001": [
        ("app.run(debug=True)\n", "app.run(debug=os.environ.get('D') == '1')\n"),
        ("app.config['DEBUG'] = True\n", "app.config['DEBUG'] = False\n"),
    ],
    "SAST-TLS-001": [("requests.get(url, verify=False)\n", "requests.get(url, verify=True)\n")],
    "SAST-JWT-001": [
        (
            "token = jwt.encode(payload, 'secret', algorithm='HS256')\n",
            "token = jwt.encode(payload, os.environ['K'], algorithm='HS256')\n",
        ),
        ("JWT_SECRET = 'secret'\n", "JWT_SECRET = os.environ['JWT_SECRET']\n"),
    ],
    "SAST-JWT-002": [
        (
            "c = jwt.decode(t, k, algorithms=['none'])\n",
            "c = jwt.decode(t, k, algorithms=['HS256'])\n",
        ),
        (
            "c = jwt.decode(t, options={'verify_signature': False})\n",
            "c = jwt.decode(t, k, algorithms=['RS256'])\n",
        ),
    ],
    "SAST-CRYPTO-001": [
        (
            "h = hashlib.md5(password.encode()).hexdigest()\n",
            "h = hashlib.sha256(data).hexdigest()\n",
        )
    ],
    "SAST-CRYPTO-002": [("c = AES.new(key, AES.MODE_ECB)\n", "c = AES.new(key, AES.MODE_GCM)\n")],
    "SAST-RAND-001": [
        (
            "reset_token = random.randint(0, 999999)\n",
            "reset_token = secrets.randbelow(1_000_000)\n",
        )
    ],
    "SAST-CORS-001": [
        (
            "def h(resp):\n    resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')\n",
            "def h(resp):\n    resp.headers['Access-Control-Allow-Origin'] = 'https://app.example.com'\n",
        ),
        (
            "CORS(app, supports_credentials=True)\n",
            "CORS(app, origins=['https://a.example'], supports_credentials=True)\n",
        ),
    ],
    "SAST-CSRF-001": [
        (
            "@csrf_exempt\ndef v(request):\n    pass\n",
            "@login_required\ndef v(request):\n    pass\n",
        ),
        ("WTF_CSRF_ENABLED = False\n", "WTF_CSRF_ENABLED = True\n"),
    ],
    "SAST-COOKIE-001": [
        (
            "resp.set_cookie('sid', v)\n",
            "resp.set_cookie('sid', v, httponly=True, secure=True, samesite='Lax')\n",
        )
    ],
    "SAST-MASSASSIGN-001": [
        (
            "def v():\n    u = User(**request.json)\n",
            "def v():\n    u = User(name=request.json['name'])\n",
        )
    ],
    "SAST-XXE-001": [
        (
            "p = etree.XMLParser(resolve_entities=True)\n",
            "p = etree.XMLParser(resolve_entities=False)\n",
        )
    ],
    "SAST-UPLOAD-001": [
        (
            "f.save(os.path.join(UP, f.filename))\n",
            "f.save(os.path.join(UP, secure_filename(f.filename)))\n",
        )
    ],
    "SAST-EXPOSE-001": [("app = Flask(__name__, static_folder='.')\n", "app = Flask(__name__)\n")],
    "SAST-HARDCODED-001": [
        ("app.secret_key = 'supersecretkey123'\n", "app.secret_key = os.environ['SECRET_KEY']\n"),
        ("DB_PASSWORD = 'Pr0dPassw0rd'\n", "DB_PASSWORD = ''\n"),
    ],
    "SAST-ERRLEAK-001": [
        (
            "def v():\n    try:\n        f()\n    except ValueError:\n        return traceback.format_exc(), 500\n",
            "def v():\n    try:\n        f()\n    except ValueError:\n        log.exception('x')\n        return 'error', 500\n",
        )
    ],
    "SAST-LOG-001": [
        ("logger.info('login %s %s', user, password)\n", "logger.info('login %s', user)\n")
    ],
    "QUAL-EXCEPT-001": [
        (
            "try:\n    f()\nexcept Exception:\n    pass\n",
            "try:\n    f()\nexcept ValueError:\n    log.warning('bad value')\n",
        )
    ],
    "QUAL-DEBUGCODE-001": [
        ("import pdb\npdb.set_trace()\n", "import logging\nlogging.debug('x')\n")
    ],
}


def run(code: str, name: str = "app.py") -> set[str]:
    file = SourceFile(root=Path(), path=Path(name), text=code, language="python")
    return {i.rule_id for i in check_python(file)}


@pytest.mark.parametrize(
    ("rule_id", "positive"),
    [(rule, pos) for rule, cases in CASES.items() for pos, _ in cases],
)
def test_positive(rule_id: str, positive: str) -> None:
    assert rule_id in run(positive), positive


@pytest.mark.parametrize(
    ("rule_id", "negative"),
    [(rule, neg) for rule, cases in CASES.items() for _, neg in cases],
)
def test_negative(rule_id: str, negative: str) -> None:
    assert rule_id not in run(negative), negative


def test_django_settings_debug() -> None:
    assert "SAST-DEBUG-001" in run("DEBUG = True\n", "settings.py")
    assert "SAST-DEBUG-001" not in run("DEBUG = True\n", "views.py")  # module constant elsewhere


def test_inline_suppression() -> None:
    assert run("app.run(debug=True)  # secscope: ignore SAST-DEBUG-001\n") == set()
    assert "SAST-DEBUG-001" in run("app.run(debug=True)  # secscope: ignore SAST-OTHER-001\n")


def test_syntax_error_is_ignored() -> None:
    assert run("def broken(:\n") == set()


def test_usedforsecurity_false_not_flagged() -> None:
    assert run("h = hashlib.md5(data, usedforsecurity=False)\n") == set()


def test_local_variable_named_request_is_not_flask_request() -> None:
    code = (
        "async def handle(request):\n"
        "    return await httpx.get(request.url)\n"
        "def other(request):\n"
        "    open(request.headers['x'])\n"
    )
    assert run(code) == set()
