<?php
// Local file inclusion: include path taken from user input.
$page = $_GET['page'] ?? 'about.php';
include __DIR__ . '/pages/' . $page;
