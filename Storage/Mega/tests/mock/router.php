<?php

/**
 * Tiny stand-in for the MEGA API used by the end-to-end test (php -S 127.0.0.1:PORT router.php).
 * Like the real server it only stores what the client sends (encrypted attributes, wrapped keys,
 * encrypted file data). Implements: us0, us (v2 login, tsid), ug, sml, uq, f, p, a, m, d, l, s2, u, g.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use AiMcp\Mega\Crypto;

const USER = 'USERHNDL';

$stateFile = getenv('MOCK_STATE') ?: sys_get_temp_dir() . '/mega-mock.json';
$base = 'http://' . $_SERVER['HTTP_HOST'];
$state = is_file($stateFile) ? json_decode((string) file_get_contents($stateFile), true) : null;
$state ??= [
    'email' => 'test@example.com',
    'password' => 'secret-password',
    'salt' => Crypto::b64encode(random_bytes(32)),
    'master' => Crypto::b64encode(random_bytes(16)),
    'nodes' => [
        'ROOTHNDL' => ['h' => 'ROOTHNDL', 't' => 2, 'ts' => time()],
        'INBXHNDL' => ['h' => 'INBXHNDL', 't' => 3, 'ts' => time()],
        'TRSHHNDL' => ['h' => 'TRSHHNDL', 't' => 4, 'ts' => time()],
    ],
    'uploads' => [],
    'blobs' => [],
    'links' => [],   // public handle => node handle
    'shares' => [],  // node handle => {ok, ha, keys: {handle: key wrapped with share key}}
    'sessions' => [],
];
$save = function () use (&$state, $stateFile): void {
    file_put_contents($stateFile, json_encode($state));
};
$handle = fn (): string => substr(Crypto::b64encode(random_bytes(6)), 0, 8);

function subtree(array $nodes, string $h): array
{
    $out = [$h];
    foreach ($nodes as $n) {
        if (($n['p'] ?? null) === $h) {
            array_push($out, ...subtree($nodes, $n['h']));
        }
    }
    return $out;
}

$path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (preg_match('~^/ul/(\w+)/(\d+)$~', $path, $m)) {
    $ul = &$state['uploads'][$m[1]];
    $data = substr(base64_decode($ul['data']), 0, (int) $m[2]) . file_get_contents('php://input');
    $ul['data'] = base64_encode($data);
    if (strlen($data) >= $ul['size']) {
        $ul['token'] = Crypto::b64encode(random_bytes(27));
        echo $ul['token'];
    }
    $save();
    exit;
}
if (preg_match('~^/dl/([\w-]+)/(\d+)-(\d+)$~', $path, $m)) {
    echo substr(base64_decode($state['blobs'][$m[1]]), (int) $m[2], (int) $m[3] - (int) $m[2] + 1);
    exit;
}

$authenticated = isset($_GET['sid']) && in_array($_GET['sid'], $state['sessions'], true);
$folderLink = isset($_GET['n']) ? ($state['links'][$_GET['n']] ?? null) : null;

$run = function (array $cmd) use (&$state, $authenticated, $folderLink, $handle, $base): mixed {
    $a = $cmd['a'];
    $public = in_array($a, ['us0', 'us'], true) || ($a === 'g' && (isset($cmd['p']) || $folderLink)) || ($a === 'f' && $folderLink);
    if (!$public && !$authenticated) {
        return -15;
    }
    switch ($a) {
        case 'us0':
            return ['v' => 2, 's' => $state['salt']];

        case 'us':
            $derived = hash_pbkdf2('sha512', $state['password'], Crypto::b64decode($state['salt']), 100000, 32, true);
            if ($cmd['user'] !== $state['email'] || $cmd['uh'] !== Crypto::b64encode(substr($derived, 16))) {
                return -9;
            }
            $master = Crypto::b64decode($state['master']);
            $rand = random_bytes(16);
            $tsid = Crypto::b64encode($rand . Crypto::aesEcbEncrypt($master, $rand));
            $state['sessions'][] = $tsid;
            return ['k' => Crypto::b64encode(Crypto::aesEcbEncrypt(substr($derived, 0, 16), $master)), 'tsid' => $tsid];

        case 'ug':
            return ['u' => USER, 'email' => $state['email'], 'name' => 'Mock User'];

        case 'sml':
            $state['sessions'] = [];
            return 0;

        case 'uq':
            return ['utype' => 0, 'cstrg' => 1234, 'mstrg' => 21474836480, 'caxfer' => 10, 'csxfer' => 0, 'mxfer' => 0];

        case 'f':
            if ($folderLink !== null) {
                $share = $state['shares'][$folderLink];
                $nodes = [];
                foreach (subtree($state['nodes'], $folderLink) as $h) {
                    $n = $state['nodes'][$h];
                    $n['k'] = $folderLink . ':' . $share['keys'][$h];
                    $nodes[] = $n;
                }
                return ['f' => $nodes];
            }
            $ok = [];
            foreach ($state['shares'] as $h => $s) {
                $ok[] = ['h' => $h, 'ha' => $s['ha'], 'k' => $s['ok']];
            }
            $ph = [];
            foreach ($state['links'] as $p => $h) {
                $ph[] = ['h' => $h, 'ph' => $p];
            }
            return ['f' => array_values($state['nodes']), 'ok' => $ok, 'ph' => $ph];

        case 'p':
            $created = [];
            $map = [];
            foreach ($cmd['n'] as $n) {
                $node = [
                    'h' => $handle(),
                    'p' => isset($n['p']) ? $map[$n['p']] : $cmd['t'],
                    't' => $n['t'],
                    'a' => $n['a'],
                    'k' => USER . ':' . $n['k'],
                    'u' => USER,
                    'ts' => time(),
                ];
                if (!isset($state['nodes'][$node['p']])) {
                    return -9;
                }
                $map[$n['h'] ?? $n['ph']] = $node['h'];
                if ($n['t'] === 0) {
                    $source = isset($n['ph']) ? $state['links'][$n['ph']] : $n['h'];
                    $upload = array_values(array_filter($state['uploads'], fn ($u) => ($u['token'] ?? null) === $source))[0] ?? null;
                    if ($upload !== null) {
                        $state['blobs'][$node['h']] = $upload['data'];
                        $node['s'] = $upload['size'];
                    } elseif (isset($state['nodes'][$source])) {
                        $state['blobs'][$node['h']] = $state['blobs'][$source];
                        $node['s'] = $state['nodes'][$source]['s'];
                    } else {
                        return -9;
                    }
                }
                $state['nodes'][$node['h']] = $node;
                $created[] = $node;
            }
            return ['f' => $created];

        case 'a':
            $state['nodes'][$cmd['n']]['a'] = $cmd['at'];
            return 0;

        case 'm':
            if (!isset($state['nodes'][$cmd['n']], $state['nodes'][$cmd['t']])) {
                return -9;
            }
            $state['nodes'][$cmd['n']]['p'] = $cmd['t'];
            return 0;

        case 'd':
            foreach (subtree($state['nodes'], $cmd['n']) as $h) {
                unset($state['nodes'][$h], $state['blobs'][$h]);
            }
            return 0;

        case 'l':
            if (!empty($cmd['d'])) {
                $state['links'] = array_filter($state['links'], fn ($h) => $h !== $cmd['n']);
                return 0;
            }
            $existing = array_search($cmd['n'], $state['links'], true);
            if ($existing !== false) {
                return $existing;
            }
            $ph = $handle();
            $state['links'][$ph] = $cmd['n'];
            return $ph;

        case 's2':
            if (($cmd['s'][0]['r'] ?? '') === '') {
                unset($state['shares'][$cmd['n']]);
                return 0;
            }
            $keys = [];
            foreach ($cmd['cr'][1] as $i => $h) {
                $keys[$h] = null;
            }
            for ($i = 0; $i < count($cmd['cr'][2]); $i += 3) {
                $keys[$cmd['cr'][1][$cmd['cr'][2][$i + 1]]] = $cmd['cr'][2][$i + 2];
            }
            $state['shares'][$cmd['n']] = ['ok' => $cmd['ok'], 'ha' => $cmd['ha'], 'keys' => $keys];
            return 0;

        case 'u':
            $id = bin2hex(random_bytes(4));
            $state['uploads'][$id] = ['size' => $cmd['s'], 'data' => ''];
            return ['p' => "{$base}/ul/{$id}"];

        case 'g':
            $h = isset($cmd['p']) ? ($state['links'][$cmd['p']] ?? null) : $cmd['n'];
            $node = $h !== null ? ($state['nodes'][$h] ?? null) : null;
            if ($node === null || $node['t'] !== 0) {
                return -9;
            }
            return ['s' => $node['s'], 'at' => $node['a']] + (!empty($cmd['g']) ? ['g' => "{$base}/dl/{$h}"] : []);

        default:
            return -2;
    }
};

$results = [];
foreach (json_decode((string) file_get_contents('php://input'), true) as $cmd) {
    $results[] = $run($cmd);
}
$save();
header('Content-Type: application/json');
echo json_encode($results);
