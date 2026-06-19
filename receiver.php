<?php
header("Content-Type: text/plain; charset=utf-8");

// CPEE sends multipart/form-data; payload is in $_POST["notification"]
if (!isset($_POST["notification"])) {
  http_response_code(400);
  echo "ERROR: missing form field 'notification'\n";
  exit;
}

$notification = $_POST["notification"];

// Call python worker; pass JSON via STDIN
$cmd = "python3 " . escapeshellarg("/srv/gruppe/students/ge83vik/worker/worker.py");
$descriptorspec = [
  0 => ["pipe", "r"],  // stdin
  1 => ["pipe", "w"],  // stdout
  2 => ["pipe", "w"]   // stderr
];

$process = proc_open($cmd, $descriptorspec, $pipes);
if (!is_resource($process)) {
  http_response_code(500);
  echo "ERROR: could not start python worker\n";
  exit;
}

fwrite($pipes[0], $notification);
fclose($pipes[0]);

$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);

$return_value = proc_close($process);

if ($return_value !== 0) {
  http_response_code(500);
  echo "ERROR: python worker failed\n";
  if ($stderr) echo $stderr . "\n";
  exit;
}

echo "OK\n";