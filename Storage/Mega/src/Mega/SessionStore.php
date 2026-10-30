<?php

declare(strict_types=1);

namespace AiMcp\Mega;

/**
 * Persists the MEGA session (sid + master key + RSA key) between HTTP requests, encrypted with
 * AES-256-GCM using a server-side secret, so that every MCP call doesn't require a new login.
 */
final class SessionStore
{
    private readonly string $file;
    private readonly string $key;

    public function __construct(string $directory, string $secret)
    {
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('mega.session_secret must be at least 32 characters');
        }
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new \RuntimeException("Cannot create storage directory {$directory}");
        }
        $this->file = rtrim($directory, '/') . '/mega-session.bin';
        $this->key = hash('sha256', $secret, true);
    }

    public function load(): ?array
    {
        if (!is_file($this->file)) {
            return null;
        }
        $blob = (string) file_get_contents($this->file);
        if (strlen($blob) < 28) {
            return null;
        }
        $plain = openssl_decrypt(substr($blob, 28), 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, substr($blob, 0, 12), substr($blob, 12, 16));
        $data = $plain === false ? null : json_decode($plain, true);
        return is_array($data) ? $data : null;
    }

    public function save(array $session): void
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt(json_encode($session, JSON_THROW_ON_ERROR), 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $iv, $tag);
        $tmp = $this->file . '.' . bin2hex(random_bytes(4));
        file_put_contents($tmp, $iv . $tag . $cipher, LOCK_EX);
        chmod($tmp, 0600);
        rename($tmp, $this->file);
    }

    public function clear(): void
    {
        if (is_file($this->file)) {
            unlink($this->file);
        }
    }
}
