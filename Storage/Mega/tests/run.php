<?php

/**
 * Test suite: php tests/run.php
 *  - crypto checked against vectors produced by megajs (tests/fixtures/megajs-vectors.json)
 *  - unit tests for helpers and argument validation
 *  - end-to-end: the MCP HTTP endpoint (public/index.php) against a mock MEGA API (tests/mock/router.php)
 */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use AiMcp\Mcp\ToolRegistry;
use AiMcp\Mega\Crypto;
use AiMcp\Mega\MegaClient;

$failures = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    echo ($ok ? "  ok   " : "  FAIL ") . $name . ($ok || $detail === '' ? '' : " -- {$detail}") . PHP_EOL;
    $failures += $ok ? 0 : 1;
}

// ------------------------------------------------------------------ crypto vs megajs
echo "Crypto (megajs vectors)\n";
$v = json_decode((string) file_get_contents(__DIR__ . '/fixtures/megajs-vectors.json'), true);
$pk = Crypto::prepareKey($v['password']);
check('v1 password key', bin2hex($pk) === $v['prepareKey']);
check('v1 e-mail hash', Crypto::stringHash($v['email'], $pk) === $v['stringHash']);

$size = $v['upload']['size'];
$data = '';
for ($i = 0; $i < $size; $i++) {
    $data .= chr(($i * 7 + 3) % 251);
}
$k24 = hex2bin($v['upload']['key24']);
[$key, $nonce] = [substr($k24, 0, 16), substr($k24, 16)];
$cipher = '';
$macs = '';
foreach (Crypto::chunks($size) as $offset => $length) {
    $chunk = substr($data, $offset, $length);
    $macs .= Crypto::chunkMac($key, $nonce, $chunk);
    $cipher .= Crypto::aesCtr($key, $nonce, $offset, $chunk);
}
check('upload ciphertext (AES-CTR)', hash('sha256', $cipher) === $v['upload']['cipherSha256']);
$meta = Crypto::metaMac($key, $macs);
$fileKey = ($key ^ ($nonce . $meta)) . $nonce . $meta;
check('file key with meta-MAC', bin2hex($fileKey) === $v['upload']['fileKey']);
$plain = Crypto::aesCtr(Crypto::fileAesKey($fileKey), substr($fileKey, 16, 8), 999984, substr($cipher, 999984, 4096));
check('ranged decryption', $plain === substr($data, 999984, 4096));
check('RSA decryption (MEGA key format)', bin2hex(Crypto::rsaDecrypt(base64_decode($v['rsa']['ciphertext']), base64_decode($v['rsa']['privk']))) === $v['rsa']['plaintext']);

// ------------------------------------------------------------------ helpers
echo "Helpers\n";
$k = random_bytes(16);
$attrs = ['n' => 'Fattura àèì €.pdf', 'lbl' => 3];
check('attribute round trip', Crypto::decryptAttributes(Crypto::encryptAttributes($attrs, $k), $k) === $attrs);
check('attribute wrong key', Crypto::decryptAttributes(Crypto::encryptAttributes($attrs, $k), random_bytes(16)) === null);
check('base64url round trip', Crypto::b64decode(Crypto::b64encode("\xff\xfe\x00abc")) === "\xff\xfe\x00abc");
$chunks = Crypto::chunks(5 * 1048576);
check('chunk layout', array_slice($chunks, 0, 3, true) === [0 => 131072, 131072 => 262144, 393216 => 393216] && array_sum($chunks) === 5 * 1048576);
check('link parse (new format)', MegaClient::parseLink('https://mega.nz/folder/AbCdEfGh#KEYkey_-123/file/IjKlMnOp') === ['type' => 'folder', 'handle' => 'AbCdEfGh', 'key' => 'KEYkey_-123', 'sub' => 'IjKlMnOp']);
check('link parse (legacy)', MegaClient::parseLink('https://mega.nz/#!AbCdEfGh!KEYkey')['type'] === 'file');
check('splitParent', MegaClient::splitParent('trash:/a/b.txt') === ['trash:/a', 'b.txt']);

$registry = new ToolRegistry();
$registry->add('t', 'T', 'test', ['n' => ['type' => 'integer', 'default' => 5, 'maximum' => 10], 's' => ['type' => 'string', 'enum' => ['a', 'b']]], ['s'], fn ($a) => $a);
check('validation: defaults', json_decode($registry->call('t', ['s' => 'a'])['content'][0]['text'], true) === ['n' => 5, 's' => 'a']);
check('validation: missing required', $registry->call('t', [])['isError'] === true);
check('validation: enum', $registry->call('t', ['s' => 'c'])['isError'] === true);
check('validation: maximum', $registry->call('t', ['s' => 'a', 'n' => 11])['isError'] === true);

// ------------------------------------------------------------------ end to end
echo "End to end (MCP over HTTP + mock MEGA API)\n";
$tmp = sys_get_temp_dir() . '/mega-mcp-test-' . bin2hex(random_bytes(4));
mkdir($tmp);
$token = bin2hex(random_bytes(32));
$mockPort = random_int(20000, 29999);
$mcpPort = $mockPort + 1;
$env = getenv() + [
    'MOCK_STATE' => "{$tmp}/mock.json",
    'MCP_AUTH_TOKENS' => $token,
    'MEGA_EMAIL' => 'test@example.com',
    'MEGA_PASSWORD' => 'secret-password',
    'MEGA_SESSION_SECRET' => bin2hex(random_bytes(32)),
    'MEGA_STORAGE_DIR' => "{$tmp}/var",
    'MEGA_API_GATEWAY' => "http://127.0.0.1:{$mockPort}/",
];
$servers = [
    proc_open([PHP_BINARY, '-S', "127.0.0.1:{$mockPort}", __DIR__ . '/mock/router.php'], [1 => ['file', "{$tmp}/mock.log", 'a'], 2 => ['file', "{$tmp}/mock.log", 'a']], $p1, null, $env),
    proc_open([PHP_BINARY, '-S', "127.0.0.1:{$mcpPort}", '-t', dirname(__DIR__) . '/public'], [1 => ['file', "{$tmp}/mcp.log", 'a'], 2 => ['file', "{$tmp}/mcp.log", 'a']], $p2, null, $env),
];
register_shutdown_function(function () use ($servers, $tmp) {
    foreach ($servers as $s) {
        proc_terminate($s);
    }
    exec('rm -rf ' . escapeshellarg($tmp));
});
usleep(700000);

function http(int $port, ?string $token, mixed $body, string $method = 'POST', array $extraHeaders = []): array
{
    $ch = curl_init("http://127.0.0.1:{$port}/");
    $headers = array_merge(['Content-Type: application/json', 'Accept: application/json, text/event-stream'], $extraHeaders);
    if ($token !== null) {
        $headers[] = "Authorization: Bearer {$token}";
    }
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers, CURLOPT_PROXY => '']);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    $out = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$status, json_decode((string) $out, true)];
}

$id = 0;
function tool(string $name, array $args = []): array
{
    global $mcpPort, $token, $id;
    [, $res] = http($mcpPort, $token, ['jsonrpc' => '2.0', 'id' => ++$id, 'method' => 'tools/call', 'params' => ['name' => $name, 'arguments' => (object) $args]]);
    $result = $res['result'] ?? ['isError' => true, 'content' => [['text' => json_encode($res)]]];
    $text = $result['content'][0]['text'] ?? '';
    return [$result['isError'] ? null : json_decode($text, true), $text];
}

$init = ['jsonrpc' => '2.0', 'id' => 0, 'method' => 'initialize', 'params' => ['protocolVersion' => '2025-06-18', 'capabilities' => new stdClass(), 'clientInfo' => ['name' => 'test', 'version' => '1']]];
check('no token -> 401', http($mcpPort, null, $init)[0] === 401);
check('wrong token -> 401', http($mcpPort, str_repeat('x', 64), $init)[0] === 401);
check('GET -> 405', http($mcpPort, $token, null, 'GET')[0] === 405);
[$status, $res] = http($mcpPort, $token, $init);
check('initialize', $status === 200 && ($res['result']['protocolVersion'] ?? null) === '2025-06-18', json_encode($res));
check('notification -> 202', http($mcpPort, $token, ['jsonrpc' => '2.0', 'method' => 'notifications/initialized'])[0] === 202);
[, $res] = http($mcpPort, $token, ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list']);
check('tools/list', count($res['result']['tools'] ?? []) >= 25, (string) count($res['result']['tools'] ?? []));

[$r, $t] = tool('mega_account_info');
check('auto login + account info', ($r['email'] ?? null) === 'test@example.com' && $r['spaceTotalHuman'] === '20.00 GB', $t);
[$r, $t] = tool('mega_mkdir', ['path' => '/Progetti/2026']);
check('mkdir -p', ($r['path'] ?? null) === '/Progetti/2026', $t);
$text = "Ciao MEGA! àèìòù €\n" . str_repeat('0123456789', 50000);
[$r, $t] = tool('mega_write_file', ['path' => '/Progetti/2026/nota.txt', 'content' => $text]);
check('write file (multi-chunk upload)', ($r['size'] ?? null) === strlen($text), $t);
[$r, $t] = tool('mega_read_file', ['path' => '/Progetti/2026/nota.txt', 'maxBytes' => 1000000]);
check('read file (download + decrypt)', ($r['content'] ?? null) === $text, substr($t, 0, 200));
[$r, $t] = tool('mega_read_file', ['path' => '/Progetti/2026/nota.txt', 'start' => 300001, 'maxBytes' => 50]);
check('read byte range', ($r['content'] ?? null) === substr($text, 300001, 50) && $r['truncated'] === true, $t);
[$r, $t] = tool('mega_write_file', ['path' => '/Progetti/2026/nota.txt', 'content' => 'x']);
check('write refuses overwrite', $r === null && str_contains($t, 'overwrite'), $t);
[$r, $t] = tool('mega_write_file', ['path' => '/Progetti/2026/nota.txt', 'content' => base64_encode("v2\x00\x01"), 'encoding' => 'base64', 'overwrite' => true]);
check('write with overwrite', ($r['size'] ?? null) === 4, $t);
[$r, $t] = tool('mega_read_file', ['path' => '/Progetti/2026/nota.txt', 'encoding' => 'base64']);
check('read base64', ($r['content'] ?? null) === base64_encode("v2\x00\x01"), $t);
[$r, $t] = tool('mega_list', ['path' => 'trash:/']);
check('replaced version in Rubbish Bin', ($r['entries'][0]['name'] ?? null) === 'nota.txt', $t);

// new request = new PHP process: the cached session and a fresh tree fetch must decrypt everything
[$r, $t] = tool('mega_list', ['path' => '/', 'recursive' => true]);
$paths = array_column($r['entries'] ?? [], 'path');
check('list recursive (fresh tree decrypt)', $paths === ['/Progetti', '/Progetti/2026', '/Progetti/2026/nota.txt'], $t);
[$r, $t] = tool('mega_rename', ['path' => '/Progetti/2026/nota.txt', 'newName' => 'appunti.bin']);
check('rename', ($r['path'] ?? null) === '/Progetti/2026/appunti.bin', $t);
[$r, $t] = tool('mega_copy', ['path' => '/Progetti/2026', 'destination' => '/']);
check('copy folder', ($r['path'] ?? null) === '/2026', $t);
[$r, $t] = tool('mega_read_file', ['path' => '/2026/appunti.bin', 'encoding' => 'base64']);
check('read copied file', ($r['content'] ?? null) === base64_encode("v2\x00\x01"), $t);
[$r, $t] = tool('mega_move', ['path' => '/2026', 'destination' => '/Progetti']);
check('move', ($r['path'] ?? null) === '/Progetti/2026', $t);
[$r, $t] = tool('mega_move', ['path' => '/Progetti', 'destination' => '/Progetti/2026']);
check('move into itself refused', $r === null, $t);
[$r, $t] = tool('mega_search', ['query' => 'APPUNTI']);
check('search (original + copy)', ($r['count'] ?? null) === 2, $t);
[$r, $t] = tool('mega_set_label', ['path' => '/Progetti', 'label' => 'green']);
check('label', ($r['label'] ?? null) === 'green', $t);
[$r, $t] = tool('mega_set_favorite', ['path' => '/Progetti']);
check('favorite', ($r['favorite'] ?? null) === true, $t);
[$r, $t] = tool('mega_get_info', ['path' => '/Progetti']);
check('attributes persisted', ($r['label'] ?? null) === 'green' && ($r['favorite'] ?? null) === true, $t);

[$r, $t] = tool('mega_create_link', ['path' => '/Progetti/2026/appunti.bin']);
$fileLink = $r['url'] ?? '';
check('file link', str_starts_with($fileLink, 'https://mega.nz/file/') && str_contains($fileLink, '#'), $t);
[$r, $t] = tool('mega_public_read', ['url' => $fileLink, 'encoding' => 'base64']);
check('public file read', ($r['content'] ?? null) === base64_encode("v2\x00\x01") && ($r['name'] ?? null) === 'appunti.bin', $t);
[$r, $t] = tool('mega_create_link', ['path' => '/Progetti']);
$folderLink = $r['url'] ?? '';
check('folder link', str_starts_with($folderLink, 'https://mega.nz/folder/'), $t);
[$r, $t] = tool('mega_public_info', ['url' => $folderLink, 'recursive' => true]);
check('public folder listing', ($r['name'] ?? null) === 'Progetti' && count($r['entries'] ?? []) === 4, $t);
[$r, $t] = tool('mega_public_read', ['url' => $folderLink, 'subPath' => '2026/appunti.bin', 'encoding' => 'base64']);
check('public folder file read', ($r['content'] ?? null) === base64_encode("v2\x00\x01"), $t);
[$r, $t] = tool('mega_list_shares');
check('list public links', count($r['publicLinks'] ?? []) === 2, $t);
[$r, $t] = tool('mega_import_link', ['url' => $fileLink, 'remoteFolder' => '/Importati']);
check('import file link', ($r['path'] ?? null) === '/Importati/appunti.bin', $t);
[$r, $t] = tool('mega_remove_link', ['path' => '/Progetti/2026/appunti.bin']);
check('remove link', ($r['linkRemoved'] ?? null) === true, $t);
[$r, $t] = tool('mega_public_read', ['url' => $fileLink]);
check('removed link no longer works', $r === null, $t);

[$r, $t] = tool('mega_delete', ['path' => '/Importati']);
check('delete to Rubbish Bin', ($r['permanent'] ?? null) === false, $t);
[$r, $t] = tool('mega_restore', ['path' => 'trash:/Importati']);
check('restore to original folder', ($r['path'] ?? null) === '/Importati', $t);
[$r, $t] = tool('mega_delete', ['path' => '/Importati', 'permanent' => true]);
check('permanent delete', ($r['deleted'] ?? null) === true, $t);
[$r, $t] = tool('mega_empty_trash');
check('empty Rubbish Bin', ($r['deleted'] ?? null) === 1, $t);
[$r, $t] = tool('mega_delete', ['path' => '/']);
check('deleting root refused', $r === null, $t);
[$r, $t] = tool('mega_upload_from_url', ['url' => 'http://127.0.0.1/secret']);
check('upload from private URL refused', $r === null && str_contains($t, 'private'), $t);
[$r, $t] = tool('mega_logout');
check('logout', ($r['loggedIn'] ?? null) === false, $t);
[$r, $t] = tool('mega_list');
check('re-login after logout', is_array($r['entries'] ?? null), $t);

echo $failures === 0 ? "\nAll tests passed\n" : "\n{$failures} test(s) failed (logs in {$tmp})\n";
exit($failures === 0 ? 0 : 1);
