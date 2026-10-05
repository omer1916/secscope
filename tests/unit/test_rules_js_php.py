"""Positive / negative cases for every native pattern rule (rules/native/*.yaml)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secscope.analysis.regex_rules import load_rules, scan_file
from secscope.analysis.source import SourceFile

RULES = load_rules()

# (rule_id, language, positive, negative)
CASES: list[tuple[str, str, str, str]] = [
    (
        "SAST-SQLI-001",
        "javascript",
        'db.query("SELECT * FROM u WHERE id = " + req.params.id);',
        'db.query("SELECT * FROM u WHERE id = ?", [id]);',
    ),
    (
        "SAST-SQLI-001",
        "javascript",
        "db.query(`SELECT * FROM u WHERE id = ${id}`);",
        "db.query('SELECT 1');",
    ),
    (
        "SAST-SQLI-001",
        "php",
        '$db->query("SELECT name FROM u WHERE id = " . $_GET["id"]);',
        '$stmt = $db->prepare("SELECT name FROM u WHERE id = ?");',
    ),
    (
        "SAST-NOSQLI-001",
        "javascript",
        "Users.findOne({ user: req.body.user, pass: req.body.pass });",
        "Users.findOne({ user: String(name) });",
    ),
    (
        "SAST-CMDI-001",
        "javascript",
        'exec("ping " + req.query.host, cb);',
        'execFile("ping", ["-c", "1", host], cb);',
    ),
    ("SAST-CMDI-001", "php", "system('ping ' . $_GET['h']);", "system('uptime');"),
    ("SAST-EVAL-001", "javascript", "eval(req.query.expr);", 'eval("1+1");'),
    ("SAST-EVAL-001", "php", "eval($code);", "evaluate($x);"),
    (
        "SAST-XSS-001",
        "javascript",
        'el.innerHTML = "Hi " + name;',
        'el.textContent = "Hi " + name;',
    ),
    (
        "SAST-XSS-001",
        "html",
        "<script>document.write(location.hash)</script>",
        "<script>console.log(1)</script>",
    ),
    (
        "SAST-XSS-002",
        "javascript",
        "<div dangerouslySetInnerHTML={{ __html: html }} />",
        "<div>{text}</div>",
    ),
    ("SAST-XSS-003", "template", "<p>{{ comment|safe }}</p>", "<p>{{ comment }}</p>"),
    ("SAST-XSS-003", "php", "echo $_GET['q'];", "echo htmlspecialchars($_GET['q'], ENT_QUOTES);"),
    ("SAST-REDIRECT-001", "javascript", "res.redirect(req.query.next);", 'res.redirect("/home");'),
    (
        "SAST-REDIRECT-001",
        "php",
        "header('Location: ' . $_GET['u']);",
        "header('Location: /home');",
    ),
    (
        "SAST-PATH-001",
        "javascript",
        "res.sendFile(path.join(dir, req.query.file));",
        'res.sendFile(path.join(dir, "index.html"));',
    ),
    (
        "SAST-LFI-001",
        "php",
        "include __DIR__ . '/pages/' . $page;",
        "include __DIR__ . '/pages/about.php';",
    ),
    (
        "SAST-SSRF-001",
        "javascript",
        "const r = await axios.get(req.query.url);",
        'const r = await axios.get("https://api.example.com");',
    ),
    ("SAST-SSRF-001", "php", "file_get_contents($_GET['url']);", "file_get_contents('data.json');"),
    (
        "SAST-DESER-001",
        "php",
        "$o = unserialize($_COOKIE['p']);",
        "$o = unserialize($s, ['allowed_classes' => false]);",
    ),
    (
        "SAST-DESER-001",
        "javascript",
        "const s = require('node-serialize');",
        "const s = require('serialize-javascript');",
    ),
    (
        "SAST-CRYPTO-001",
        "javascript",
        'crypto.createHash("md5").update(pw);',
        'crypto.createHash("sha256").update(data);',
    ),
    (
        "SAST-CRYPTO-001",
        "php",
        "$h = md5($password);",
        "$h = password_hash($password, PASSWORD_DEFAULT);",
    ),
    (
        "SAST-CRYPTO-002",
        "javascript",
        'crypto.createCipheriv("aes-128-ecb", k, null);',
        'crypto.createCipheriv("aes-256-gcm", k, iv);',
    ),
    (
        "SAST-RAND-001",
        "javascript",
        "const resetToken = Math.random().toString(36);",
        "const offset = Math.random() * 10;",
    ),
    (
        "SAST-TLS-001",
        "javascript",
        "https.get(u, { rejectUnauthorized: false });",
        "https.get(u, { rejectUnauthorized: true });",
    ),
    (
        "SAST-TLS-001",
        "php",
        "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);",
        "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);",
    ),
    (
        "SAST-JWT-001",
        "javascript",
        'const JWT_SECRET = "changeme";',
        "const JWT_SECRET = process.env.JWT_SECRET;",
    ),
    (
        "SAST-JWT-002",
        "javascript",
        'if (header.alg === "none") return payload;',
        'jwt.verify(t, k, { algorithms: ["HS256"] });',
    ),
    (
        "SAST-CORS-001",
        "javascript",
        'res.setHeader("Access-Control-Allow-Origin", req.headers.origin);',
        'res.setHeader("Access-Control-Allow-Origin", "https://a.example");',
    ),
    (
        "SAST-CORS-001",
        "php",
        "header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);",
        "header('Access-Control-Allow-Origin: https://a.example');",
    ),
    (
        "SAST-PROTO-001",
        "javascript",
        "const s = _.merge({}, req.body);",
        "const s = _.merge({}, defaults);",
    ),
    (
        "SAST-MASSASSIGN-001",
        "javascript",
        "await User.create(req.body);",
        "await User.create({ name, email });",
    ),
    (
        "SAST-STORAGE-001",
        "javascript",
        'localStorage.setItem("authToken", t);',
        'localStorage.setItem("theme", "dark");',
    ),
    (
        "SAST-COOKIE-001",
        "javascript",
        'res.cookie("sid", id);',
        'res.cookie("sid", id, { httpOnly: true, secure: true });',
    ),
    (
        "SAST-LOG-001",
        "javascript",
        "console.log('pw', password);",
        "console.log('user logged in', user.id);",
    ),
    (
        "SAST-HARDCODED-001",
        "javascript",
        'const apiKey = "sk9fA8dkL2mQ";',
        "const apiKey = process.env.API_KEY;",
    ),
    (
        "SAST-HARDCODED-001",
        "php",
        '$db_password = "S3cr3tPass!";',
        "$db_password = getenv('DB_PASSWORD');",
    ),
    (
        "SAST-ERRLEAK-001",
        "javascript",
        "res.status(500).send(e.stack);",
        'res.status(500).json({ error: "internal" });',
    ),
    ("SAST-DEBUG-001", "php", "ini_set('display_errors', '1');", "ini_set('display_errors', '0');"),
    ("SAST-PHPINFO-001", "php", "<?php phpinfo(); ?>", "<?php echo 'info'; ?>"),
    ("QUAL-DEBUGCODE-001", "javascript", "  debugger;", "  // debugger is not used"),
    ("QUAL-DEBUGCODE-001", "php", "var_dump($_POST);", "var_dump($localValue);"),
    (
        "QUAL-DEFAULTCRED-001",
        "javascript",
        'login("admin", "admin");',
        '// login("admin", "admin") example in a comment',
    ),
]

_EXT = {
    "javascript": "app.js",
    "php": "index.php",
    "html": "index.html",
    "template": "templates/page.html",
}


def run(language: str, code: str) -> set[str]:
    file = SourceFile(root=Path(), path=Path(_EXT[language]), text=code + "\n", language=language)
    return {m.rule.id for m in scan_file(file, RULES)}


@pytest.mark.parametrize(("rule_id", "language", "positive", "negative"), CASES)
def test_rule(rule_id: str, language: str, positive: str, negative: str) -> None:
    assert rule_id in run(language, positive), f"positive missed: {positive}"
    assert rule_id not in run(language, negative), f"negative matched: {negative}"


def test_every_pattern_rule_has_a_case() -> None:
    covered = {c[0] for c in CASES}
    assert {r.id for r in RULES} <= covered


def test_minified_files_are_skipped() -> None:
    code = "var a=1;" * 2000 + "el.innerHTML=x;"
    file = SourceFile(root=Path(), path=Path("bundle.min.js"), text=code, language="javascript")
    assert list(scan_file(file, RULES)) == []


def test_bad_rule_file_rejected(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("- id: X-1\n  languages: [javascript]\n  pattern: '('\n")
    with pytest.raises(ValueError, match="bad rule"):
        load_rules(tmp_path)
