<?php

declare(strict_types=1);

namespace AiMcp\Mega;

/** Thin HTTP client for the MEGA JSON API (https://g.api.mega.co.nz/cs) and transfer servers. */
final class ApiClient
{
    public const DEFAULT_GATEWAY = 'https://g.api.mega.co.nz/';
    private const MAX_RETRIES = 6;

    private int $sequence;
    private ?string $sid = null;

    public function __construct(
        private readonly string $gateway = self::DEFAULT_GATEWAY,
        private readonly int $timeout = 120,
    ) {
        $this->sequence = random_int(0, 0x7FFFFFFF);
    }

    public function setSid(?string $sid): void
    {
        $this->sid = $sid;
    }

    /**
     * Sends one API command and returns its result. Negative integer results raise MegaException.
     * $query adds URL parameters (e.g. ['n' => folderHandle] for public folder links).
     */
    public function request(array $command, array $query = [], bool $anonymous = false): mixed
    {
        $params = ['id' => $this->sequence++];
        if ($this->sid !== null && !$anonymous) {
            $params['sid'] = $this->sid;
        }
        $url = rtrim($this->gateway, '/') . '/cs?' . http_build_query($params + $query);
        $body = json_encode([$command], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        for ($attempt = 0; ; $attempt++) {
            $raw = $this->http('POST', $url, $body, 'application/json');
            $decoded = json_decode($raw, true);
            $result = is_array($decoded) && array_is_list($decoded) ? ($decoded[0] ?? null) : $decoded;
            if (is_array($result) && count($result) === 1 && isset($result['err']) && is_int($result['err'])) {
                $result = $result['err'];
            }
            if (is_int($result) && $result < 0) {
                if (($result === -3 || $result === -4 || $result === -18) && $attempt < self::MAX_RETRIES) {
                    usleep((int) (250000 * 2 ** $attempt));
                    continue;
                }
                throw MegaException::fromApiCode($result);
            }
            return $result;
        }
    }

    /** POSTs raw bytes (used for uploads). Returns the response body. */
    public function post(string $url, string $data): string
    {
        return $this->http('POST', $url, $data, 'application/octet-stream');
    }

    /** GETs a URL (used for downloads; MEGA ranges are encoded as "/start-end" in the URL). */
    public function get(string $url): string
    {
        return $this->http('GET', $url, null, null);
    }

    private function http(string $method, string $url, ?string $body, ?string $contentType): string
    {
        for ($attempt = 0; ; $attempt++) {
            $ch = curl_init($url);
            $headers = ['User-Agent: ai-mcp-mega/1.0'];
            if ($contentType !== null) {
                $headers[] = "Content-Type: {$contentType}";
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_CONNECTTIMEOUT => 20,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_FOLLOWLOCATION => true,
            ]);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
            $response = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            $retryable = $response === false || $status >= 500;
            if ($retryable && $attempt < 3) {
                usleep((int) (500000 * 2 ** $attempt));
                continue;
            }
            if ($response === false) {
                throw new MegaException("HTTP request to MEGA failed: {$error}");
            }
            if ($status >= 400) {
                throw new MegaException("MEGA server returned HTTP {$status}");
            }
            return (string) $response;
        }
    }
}
