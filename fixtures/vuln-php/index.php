<?php
// Deliberately vulnerable PHP app for SecScope tests. Loopback only. DO NOT DEPLOY.
$db = new PDO('sqlite:' . __DIR__ . '/app.db');
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)');

if (isset($_GET['id'])) {
    // SQL injection: string concatenation
    $rows = $db->query("SELECT name, email FROM users WHERE id = " . $_GET['id']);
    foreach ($rows as $row) {
        echo "<p>" . $row['name'] . "</p>"; // unescaped output
    }
}

if (isset($_COOKIE['prefs'])) {
    $prefs = unserialize(base64_decode($_COOKIE['prefs'])); // insecure deserialization
}
?>
<html><head><title>Vuln PHP</title></head>
<body>
<h1>Vuln PHP</h1>
<a href="?id=1">user 1</a>
<a href="page.php?page=about.php">about</a>
</body></html>
