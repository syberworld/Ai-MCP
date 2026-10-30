<?php

declare(strict_types=1);

namespace AiMcp\Mcp;

/**
 * Minimal MCP server over the Streamable HTTP transport (stateless, JSON responses).
 * Every request must carry a valid bearer token.
 */
final class HttpServer
{
    private const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

    /**
     * @param string[] $tokens accepted bearer tokens
     * @param string[] $allowedOrigins if non-empty, browser requests from other origins are rejected
     */
    public function __construct(
        private readonly ToolRegistry $tools,
        private readonly array $tokens,
        private readonly array $allowedOrigins,
        private readonly bool $allowQueryToken,
        private readonly string $instructions,
        private readonly array $serverInfo = ['name' => 'mega-mcp', 'version' => '2.0.0'],
    ) {
        foreach ($tokens as $token) {
            if (strlen($token) < 32) {
                throw new \InvalidArgumentException('Every auth token must be at least 32 characters long');
            }
        }
        if ($tokens === []) {
            throw new \InvalidArgumentException('No auth token configured: access would be unrestricted');
        }
    }

    public function handle(): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if ($origin !== null && $this->allowedOrigins !== [] && !in_array($origin, $this->allowedOrigins, true)) {
            $this->respond(403, ['error' => 'origin not allowed']);
            return;
        }
        if (!$this->authorized()) {
            header('WWW-Authenticate: Bearer realm="mega-mcp"');
            $this->respond(401, ['error' => 'unauthorized']);
            return;
        }

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method !== 'POST') {
            header('Allow: POST');
            $this->respond(405, ['error' => 'method not allowed: this server only accepts POST (no SSE stream)']);
            return;
        }

        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) {
            $this->respond(400, self::error(null, -32700, 'Parse error'));
            return;
        }

        if (array_is_list($body) && $body !== []) {
            $responses = array_values(array_filter(array_map(fn ($m) => is_array($m) ? $this->dispatch($m) : self::error(null, -32600, 'Invalid Request'), $body)));
            $responses === [] ? $this->respond(202, null) : $this->respond(200, $responses);
            return;
        }
        $response = $this->dispatch($body);
        $response === null ? $this->respond(202, null) : $this->respond(200, $response);
    }

    private function authorized(): bool
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if ($header === '' && function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strcasecmp($name, 'Authorization') === 0) {
                    $header = $value;
                }
            }
        }
        $presented = null;
        if (preg_match('/^Bearer\s+(\S+)$/i', trim($header), $m)) {
            $presented = $m[1];
        } elseif ($this->allowQueryToken && isset($_GET['token']) && is_string($_GET['token'])) {
            $presented = $_GET['token'];
        }
        if ($presented === null) {
            return false;
        }
        $ok = false;
        foreach ($this->tokens as $token) {
            $ok = hash_equals($token, $presented) || $ok;
        }
        return $ok;
    }

    private function dispatch(array $message): ?array
    {
        $id = $message['id'] ?? null;
        $method = $message['method'] ?? null;
        $isNotification = !array_key_exists('id', $message);

        if (($message['jsonrpc'] ?? null) !== '2.0' || !is_string($method)) {
            // Responses from the client (e.g. to server requests) are not used: ignore them.
            return $isNotification || isset($message['result']) || isset($message['error'])
                ? null
                : self::error($id, -32600, 'Invalid Request');
        }
        if ($isNotification) {
            return null;
        }
        $params = is_array($message['params'] ?? null) ? $message['params'] : [];

        return match ($method) {
            'initialize' => self::result($id, [
                'protocolVersion' => in_array($params['protocolVersion'] ?? null, self::PROTOCOL_VERSIONS, true)
                    ? $params['protocolVersion']
                    : self::PROTOCOL_VERSIONS[0],
                'capabilities' => ['tools' => ['listChanged' => false]],
                'serverInfo' => $this->serverInfo,
                'instructions' => $this->instructions,
            ]),
            'ping' => self::result($id, new \stdClass()),
            'tools/list' => self::result($id, ['tools' => $this->tools->definitions()]),
            'tools/call' => $this->callTool($id, $params),
            default => self::error($id, -32601, "Method not found: {$method}"),
        };
    }

    private function callTool(mixed $id, array $params): array
    {
        $name = $params['name'] ?? null;
        if (!is_string($name) || !$this->tools->has($name)) {
            return self::error($id, -32602, 'Unknown tool: ' . (is_string($name) ? $name : '(none)'));
        }
        $arguments = is_array($params['arguments'] ?? null) ? $params['arguments'] : [];
        return self::result($id, $this->tools->call($name, $arguments));
    }

    private static function result(mixed $id, mixed $result): array
    {
        return ['jsonrpc' => '2.0', 'id' => $id, 'result' => $result];
    }

    private static function error(mixed $id, int $code, string $message): array
    {
        return ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => $code, 'message' => $message]];
    }

    private function respond(int $status, mixed $payload): void
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        if ($payload !== null) {
            header('Content-Type: application/json');
            echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        }
    }
}
