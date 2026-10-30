<?php

declare(strict_types=1);

use AiMcp\Mcp\HttpServer;
use AiMcp\Mcp\ToolRegistry;
use AiMcp\Mega\ApiClient;
use AiMcp\Mega\MegaClient;
use AiMcp\Mega\SessionStore;
use AiMcp\Tools\MegaTools;

require dirname(__DIR__) . '/vendor/autoload.php';

ini_set('display_errors', '0');
set_time_limit(0);

$configFile = dirname(__DIR__) . '/config/config.php';
$config = is_file($configFile) ? require $configFile : [];

$env = static fn (string $name): ?string => ($v = getenv($name)) !== false && $v !== '' ? $v : null;

$tokens = ($t = $env('MCP_AUTH_TOKENS')) !== null
    ? array_values(array_filter(array_map('trim', explode(',', $t))))
    : array_values(array_filter($config['auth_tokens'] ?? []));
$mega = $config['mega'] ?? [];
$limits = $config['limits'] ?? [];

try {
    $client = new MegaClient(
        new ApiClient($env('MEGA_API_GATEWAY') ?? ApiClient::DEFAULT_GATEWAY),
        new SessionStore(
            $env('MEGA_STORAGE_DIR') ?? ($mega['storage_dir'] ?? dirname(__DIR__) . '/var'),
            $env('MEGA_SESSION_SECRET') ?? (string) ($mega['session_secret'] ?? ''),
        ),
        $env('MEGA_EMAIL') ?? ($mega['email'] ?? null),
        $env('MEGA_PASSWORD') ?? ($mega['password'] ?? null),
    );

    $registry = new ToolRegistry();
    (new MegaTools(
        $client,
        (int) ($limits['max_read_bytes'] ?? 10 * 1024 * 1024),
        (int) ($limits['max_upload_bytes'] ?? 200 * 1024 * 1024),
    ))->register($registry);

    $server = new HttpServer(
        $registry,
        $tokens,
        $config['allowed_origins'] ?? [],
        (bool) ($config['allow_query_token'] ?? false),
        'Tools to manage a MEGA (mega.io) cloud drive: browse, search, read/write files, upload from URL, '
        . 'move/copy/rename/delete/restore, public links, incoming shares, imports and account quota. '
        . 'Remote paths start at the Cloud Drive root "/"; use "trash:/", "inbox:/", "shares:/<name>/" or "id:<handle>" for other locations.',
    );
} catch (\Throwable $e) {
    error_log('mega-mcp configuration error: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'server misconfigured, see server error log']);
    exit;
}

$server->handle();
