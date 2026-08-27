"""Rule-pack contract tests: every rule in the extended packs must fire on a
vulnerable snippet and stay quiet on a safe one.

This is the precision guard for the regex engine. A rule that matches
everything passes the "vulnerable" half and fails the "safe" half, so both
halves are required for every rule in these packs.
"""
import os

import pytest

from ironclad.core.walker import DiscoveredFile
from ironclad.rules.schema import load_rule_packs
from ironclad.scanners.rule_engine import scan_file_with_rules

PACK_DIR = os.path.join(os.path.dirname(__file__), "..", "ironclad", "rules", "packs")
EXTENDED_PACKS = ("java.yml", "go.yml", "php.yml", "ruby.yml", "python_extra.yml")

# rule id -> (language, vulnerable source, safe source)
CASES = {
    "JAVA-SQL-CONCATENATION": (
        "java",
        'Statement s = conn.createStatement();\nResultSet r = s.executeQuery("SELECT * FROM u WHERE id=" + userId);\n',
        'PreparedStatement p = conn.prepareStatement("SELECT * FROM u WHERE id = ?");\np.setString(1, userId);\n',
    ),
    "JAVA-OBJECT-DESERIALIZATION": (
        "java",
        "Object obj = new ObjectInputStream(socket.getInputStream()).readObject();\n",
        "UserDto dto = objectMapper.readValue(bytes, UserDto.class);\n",
    ),
    "JAVA-XXE-DOCUMENT-BUILDER": (
        "java",
        "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);\n",
        "Document doc = hardenedParserFactory().newDocumentBuilder().parse(input);\n",
    ),
    "JAVA-WEAK-RANDOM-SECURITY": (
        "java",
        "String token = String.valueOf(new Random().nextLong());\n",
        "byte[] buf = new byte[32];\nnew SecureRandom().nextBytes(buf);\n",
    ),
    "JAVA-MESSAGE-DIGEST-MD5": (
        "java",
        'MessageDigest md = MessageDigest.getInstance("MD5");\n',
        'MessageDigest md = MessageDigest.getInstance("SHA-256");\n',
    ),
    "JAVA-RUNTIME-EXEC-CONCAT": (
        "java",
        'Runtime.getRuntime().exec("convert " + userPath);\n',
        'new ProcessBuilder(List.of("convert", validatedPath)).start();\n',
    ),
    "GO-SQL-CONCATENATION": (
        "go",
        'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = \'%s\'", name))\n',
        'rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)\n',
    ),
    "GO-UNESCAPED-TEMPLATE": (
        "go",
        'import "text/template"\n',
        'import "html/template"\n',
    ),
    "GO-WEAK-RANDOM-SECURITY": (
        "go",
        'import "math/rand"\n',
        'import "crypto/rand"\n',
    ),
    "GO-UNSAFE-POINTER": (
        "go",
        'import "unsafe"\n',
        'import "encoding/binary"\n',
    ),
    "GO-IGNORING-TLS-ERROR": (
        "go",
        "_ = conn.Handshake()\n",
        "if err := conn.Handshake(); err != nil {\n\treturn err\n}\n",
    ),
    "PHP-SUPERGLOBAL-IN-SQL": (
        "php",
        '<?php $db->query("SELECT * FROM users WHERE id=" . $_GET["id"]); ?>\n',
        '<?php $st = $db->prepare("SELECT * FROM users WHERE id = ?"); $st->execute([$_GET["id"]]); ?>\n',
    ),
    "PHP-ECHO-SUPERGLOBAL": (
        "php",
        '<?php echo $_GET["name"]; ?>\n',
        '<?php echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8"); ?>\n',
    ),
    "PHP-DYNAMIC-INCLUDE": (
        "php",
        '<?php include($_GET["page"] . ".php"); ?>\n',
        '<?php $page = $allowed[$_GET["page"]] ?? "home"; include($page . ".php"); ?>\n',
    ),
    "PHP-COMMAND-SUPERGLOBAL": (
        "php",
        '<?php system("ping " . $_GET["host"]); ?>\n',
        '<?php system("ping " . escapeshellarg($validatedHost)); ?>\n',
    ),
    "PHP-WEAK-PASSWORD-HASH": (
        "php",
        '<?php $hash = md5($password); ?>\n',
        '<?php $hash = password_hash($password, PASSWORD_ARGON2ID); ?>\n',
    ),
    "RUBY-SYSTEM-INTERPOLATION": (
        "ruby",
        'system("convert #{user_path}")\n',
        "system('convert', validated_path)\n",
    ),
    "RUBY-SQL-INTERPOLATION": (
        "ruby",
        'User.where("name = \'#{params[:name]}\'")\n',
        "User.where('name = ?', params[:name])\n",
    ),
    "RUBY-EVAL-USE": (
        "ruby",
        "result = eval(user_expression)\n",
        "result = EXPRESSIONS.fetch(user_expression).call\n",
    ),
    "RUBY-SEND-FROM-PARAMS": (
        "ruby",
        "record.send(params[:method])\n",
        "record.public_send(ALLOWED.fetch(params[:method]))\n",
    ),
    "JWT-ALGORITHM-NONE": (
        "python",
        'jwt.decode(token, options={"algorithms": ["none"]})\n',
        'jwt.decode(token, key, algorithms=["RS256"])\n',
    ),
    "PY-DJANGO-DEBUG-TRUE": (
        "python",
        "DEBUG = True\n",
        "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n",
    ),
    "PY-DJANGO-SECRET-HARDCODED": (
        "python",
        "SECRET_KEY = 'a-really-long-hardcoded-secret-value'\n",
        "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n",
    ),
    "PY-ALLOWED-HOSTS-WILDCARD": (
        "python",
        "ALLOWED_HOSTS = ['*']\n",
        "ALLOWED_HOSTS = ['app.example.com']\n",
    ),
    "PY-PICKLE-REQUEST-DATA": (
        "python",
        "obj = pickle.loads(request.body)\n",
        "obj = json.loads(request.body)\n",
    ),
    # Pre-existing rules in the same packs -- covered by the same contract.
    "JAVA-WEAK-CIPHER-ECB": (
        "java",
        'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n',
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n',
    ),
    "JAVA-TRUST-ALL-CERTS": (
        "java",
        "public void checkServerTrusted(X509Certificate[] chain, String authType) { }\n",
        "public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
        "        throws CertificateException {\n    defaultManager.checkServerTrusted(chain, authType);\n}\n",
    ),
    "GO-INSECURE-SKIP-VERIFY": (
        "go",
        "tlsConfig := &tls.Config{InsecureSkipVerify: true}\n",
        "tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}\n",
    ),
    "GO-COMMAND-INJECTION": (
        "go",
        "out, err := exec.Command(userCmd).Output()\n",
        'out, err := exec.Command("git", "status").Output()\n',
    ),
    "RUBY-MASS-ASSIGNMENT": (
        "ruby",
        "User.new(params[:user])\n",
        "User.new(params.require(:user).permit(:name, :email))\n",
    ),
    "RUBY-YAML-LOAD": (
        "ruby",
        "config = YAML.load(File.read(path))\n",
        "config = YAML.safe_load(File.read(path))\n",
    ),
    "PHP-EVAL-USE": (
        "php",
        "<?php eval($code); ?>\n",
        "<?php $value = (int) $code; ?>\n",
    ),
    "PHP-SQL-CONCAT": (
        "php",
        '<?php $db->query("SELECT * FROM t WHERE id=" . $id); ?>\n',
        '<?php $st = $db->prepare("SELECT * FROM t WHERE id = ?"); $st->execute([$id]); ?>\n',
    ),
    "PHP-UNSERIALIZE-USE": (
        "php",
        "<?php $obj = unserialize($_COOKIE['session']); ?>\n",
        "<?php $obj = json_decode($_COOKIE['session'], true); ?>\n",
    ),
}


def _rules():
    return load_rule_packs([PACK_DIR])


def _discovered(tmp_path, language, source):
    extension = {"java": ".java", "go": ".go", "php": ".php", "ruby": ".rb",
                 "python": ".py", "javascript": ".js"}[language]
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"snippet{extension}"
    path.write_text(source, encoding="utf-8")
    return DiscoveredFile(path=str(path), rel_path=path.name, language=language,
                          size_bytes=len(source))


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_vulnerable_and_not_on_safe(tmp_path, rule_id):
    language, vulnerable, safe = CASES[rule_id]
    rules = _rules()

    hit = scan_file_with_rules(_discovered(tmp_path, language, vulnerable), rules)
    assert rule_id in {f.rule_id for f in hit}, f"{rule_id} did not fire on its vulnerable snippet"

    clean = scan_file_with_rules(_discovered(tmp_path / "safe", language, safe), rules)
    assert rule_id not in {f.rule_id for f in clean}, f"{rule_id} fired on its safe snippet"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_metadata_is_complete(rule_id):
    rule = next(r for r in _rules() if r.id == rule_id)
    assert rule.title and rule.message
    assert rule.remediation, f"{rule_id} has no remediation text"
    assert rule.severity in {"critical", "high", "medium", "low", "info"}
    assert rule.confidence in {"low", "medium", "high"}
    assert rule.category
    assert rule.cwe and rule.cwe.startswith("CWE-")
    assert rule.compiled_pattern is not None


def test_every_extended_pack_rule_has_a_case():
    extended_ids = set()
    for pack in EXTENDED_PACKS:
        path = os.path.join(PACK_DIR, pack)
        for rule in load_rule_packs([os.path.dirname(path)]):
            if _belongs_to(pack, rule.id):
                extended_ids.add(rule.id)
    missing = extended_ids - set(CASES)
    assert not missing, f"rules without vulnerable/safe cases: {sorted(missing)}"


def _belongs_to(pack: str, rule_id: str) -> bool:
    prefix = {
        "java.yml": ("JAVA-",),
        "go.yml": ("GO-",),
        "php.yml": ("PHP-",),
        "ruby.yml": ("RUBY-",),
        "python_extra.yml": ("PY-DJANGO", "PY-ALLOWED", "PY-PICKLE", "JWT-"),
    }[pack]
    return rule_id.startswith(prefix)


def test_no_duplicate_rule_ids_across_packs():
    ids = [rule.id for rule in _rules()]
    duplicates = {rule_id for rule_id in ids if ids.count(rule_id) > 1}
    assert not duplicates, f"duplicate rule ids: {sorted(duplicates)}"


def test_rule_pack_grew_beyond_the_v1_baseline():
    assert len(_rules()) >= 60
