<?php

declare(strict_types=1);

namespace AiMcp\Tools;

use AiMcp\Mega\MegaException;

/**
 * Downloads a public http(s) URL to a temporary stream for mega_upload_from_url.
 * Private, loopback and reserved addresses are refused (also after redirects) to prevent SSRF.
 */
final class UrlFetcher
{
    private const MAX_REDIRECTS = 5;

    /** @return array{0: resource, 1: int, 2: string} stream (rewound), size, suggested file name */
    public static function fetch(string $url, int $maxBytes): array
    {
        $stream = tmpfile();
        try {
            for ($i = 0; $i <= self::MAX_REDIRECTS; $i++) {
                [$host, $port, $ip] = self::checkUrl($url);
                ftruncate($stream, 0);
                rewind($stream);
                $ch = curl_init($url);
                curl_setopt_array($ch, [
                    CURLOPT_FILE => $stream,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_RESOLVE => ["{$host}:{$port}:{$ip}"],
                    CURLOPT_CONNECTTIMEOUT => 20,
                    CURLOPT_TIMEOUT => 600,
                    CURLOPT_USERAGENT => 'ai-mcp-mega/1.0',
                    CURLOPT_NOPROGRESS => false,
                    CURLOPT_PROGRESSFUNCTION => fn ($ch, $dlTotal, $dlNow) => ($dlTotal > $maxBytes || $dlNow > $maxBytes) ? 1 : 0,
                ]);
                $ok = curl_exec($ch);
                $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $location = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
                $error = curl_error($ch);
                curl_close($ch);

                if ($ok === false) {
                    throw new MegaException(str_contains($error, 'callback') ? 'Remote file exceeds max_upload_bytes' : "Download failed: {$error}");
                }
                if ($status >= 300 && $status < 400 && is_string($location) && $location !== '') {
                    $url = $location;
                    continue;
                }
                if ($status >= 400) {
                    throw new MegaException("Download failed: HTTP {$status}");
                }
                $size = (int) fstat($stream)['size'];
                rewind($stream);
                $name = rawurldecode(basename((string) parse_url($url, PHP_URL_PATH)));
                return [$stream, $size, $name !== '' && $name !== '/' ? $name : 'download'];
            }
            throw new MegaException('Too many redirects');
        } catch (\Throwable $e) {
            fclose($stream);
            throw $e;
        }
    }

    /** @return array{0: string, 1: int, 2: string} host, port, public IP to connect to */
    private static function checkUrl(string $url): array
    {
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = $parts['host'] ?? '';
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new MegaException('Only http(s) URLs are allowed');
        }
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $bareHost = trim($host, '[]');
        $ips = filter_var($bareHost, FILTER_VALIDATE_IP) ? [$bareHost] : (gethostbynamel($bareHost) ?: []);
        if ($ips === []) {
            throw new MegaException("Cannot resolve host {$host}");
        }
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new MegaException('URLs pointing to private or reserved addresses are not allowed');
            }
        }
        return [$bareHost, $port, $ips[0]];
    }
}
