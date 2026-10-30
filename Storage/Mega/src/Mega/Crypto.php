<?php

declare(strict_types=1);

namespace AiMcp\Mega;

use phpseclib3\Math\BigInteger;

/**
 * MEGA client-side cryptography (AES-128 ECB/CBC/CTR, CBC-MAC, password key derivation, raw RSA).
 * All keys and blocks are binary strings.
 */
final class Crypto
{
    private const ZERO_IV = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    private const RAW = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

    public static function b64encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function b64decode(string $data): string
    {
        $data = strtr(str_replace(',', '', trim($data)), '-_', '+/');
        $pad = strlen($data) % 4;
        if ($pad !== 0) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $bin = base64_decode($data, true);
        if ($bin === false) {
            throw new MegaException('Invalid base64 data');
        }
        return $bin;
    }

    public static function aesEcbEncrypt(string $key, string $data): string
    {
        return self::openssl('encrypt', 'aes-128-ecb', $key, $data, '');
    }

    public static function aesEcbDecrypt(string $key, string $data): string
    {
        return self::openssl('decrypt', 'aes-128-ecb', $key, $data, '');
    }

    public static function aesCbcEncrypt(string $key, string $data, string $iv = self::ZERO_IV): string
    {
        return self::openssl('encrypt', 'aes-128-cbc', $key, $data, $iv);
    }

    public static function aesCbcDecrypt(string $key, string $data, string $iv = self::ZERO_IV): string
    {
        return self::openssl('decrypt', 'aes-128-cbc', $key, $data, $iv);
    }

    /** AES-128-CTR as used for file contents. $offset must be a multiple of 16. */
    public static function aesCtr(string $key, string $nonce, int $offset, string $data): string
    {
        if ($offset % 16 !== 0) {
            throw new \InvalidArgumentException('CTR offset must be block aligned');
        }
        if ($data === '') {
            return '';
        }
        $iv = $nonce . pack('J', intdiv($offset, 16));
        $out = openssl_encrypt($data, 'aes-128-ctr', $key, OPENSSL_RAW_DATA, $iv);
        if ($out === false) {
            throw new MegaException('AES-CTR failure');
        }
        return $out;
    }

    /** CBC-MAC of one upload chunk (IV = nonce || nonce). */
    public static function chunkMac(string $key, string $nonce, string $chunk): string
    {
        return substr(self::aesCbcEncrypt($key, self::zeroPad($chunk), $nonce . $nonce), -16);
    }

    /** Condenses the chunk MACs into the 8-byte meta-MAC stored in the file key. */
    public static function metaMac(string $key, string $chunkMacs): string
    {
        $mac = $chunkMacs === '' ? self::ZERO_IV : substr(self::aesCbcEncrypt($key, $chunkMacs), -16);
        return (substr($mac, 0, 4) ^ substr($mac, 4, 4)) . (substr($mac, 8, 4) ^ substr($mac, 12, 4));
    }

    /** MEGA upload chunk layout: 128K, 256K, ... 1M, then 1M chunks. Returns [offset => length]. */
    public static function chunks(int $size): array
    {
        $chunks = [];
        $offset = 0;
        for ($i = 1; $offset < $size; $i++) {
            $length = $i <= 8 ? $i * 131072 : 1048576;
            $chunks[$offset] = min($length, $size - $offset);
            $offset += $length;
        }
        return $chunks;
    }

    public static function zeroPad(string $data, int $block = 16): string
    {
        $rem = strlen($data) % $block;
        return ($rem === 0 && $data !== '') ? $data : $data . str_repeat("\0", $rem === 0 ? $block : $block - $rem);
    }

    /** Legacy (v1 account) password key derivation. */
    public static function prepareKey(string $password): string
    {
        $blocks = str_split(self::zeroPad($password), 16);
        $pkey = pack('N*', 0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56);
        for ($r = 0; $r < 65536; $r++) {
            foreach ($blocks as $block) {
                $pkey = self::aesEcbEncrypt($block, $pkey);
            }
        }
        return $pkey;
    }

    /** Legacy (v1 account) e-mail hash sent as "uh" during login. */
    public static function stringHash(string $text, string $key): string
    {
        $h = self::ZERO_IV;
        foreach (str_split(self::zeroPad($text), 16) as $block) {
            $h ^= $block;
        }
        for ($r = 0; $r < 16384; $r++) {
            $h = self::aesEcbEncrypt($key, $h);
        }
        return self::b64encode(substr($h, 0, 4) . substr($h, 8, 4));
    }

    /** Decrypts the node attribute blob ("MEGA{json}"). Returns null if the key is wrong. */
    public static function decryptAttributes(string $at, string $key): ?array
    {
        $data = rtrim(self::aesCbcDecrypt($key, self::b64decode($at)), "\0");
        if (!str_starts_with($data, 'MEGA{')) {
            return null;
        }
        $attrs = json_decode(substr($data, 4), true);
        return is_array($attrs) ? $attrs : null;
    }

    public static function encryptAttributes(array $attrs, string $key): string
    {
        $json = json_encode((object) $attrs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        return self::b64encode(self::aesCbcEncrypt($key, self::zeroPad('MEGA' . $json)));
    }

    /** File keys are 32 bytes: AES key XOR (nonce || meta-MAC), nonce, meta-MAC. */
    public static function fileAesKey(string $key): string
    {
        return strlen($key) === 32 ? substr($key, 0, 16) ^ substr($key, 16, 16) : $key;
    }

    /** Parses MEGA's MPI encoding (2-byte bit length + big-endian bytes). Returns [values, rest]. */
    public static function readMpis(string $data, int $count): array
    {
        $values = [];
        $pos = 0;
        for ($i = 0; $i < $count; $i++) {
            if ($pos + 2 > strlen($data)) {
                throw new MegaException('Truncated RSA key data');
            }
            $bits = unpack('n', substr($data, $pos, 2))[1];
            $bytes = intdiv($bits + 7, 8);
            $values[] = new BigInteger(substr($data, $pos + 2, $bytes), 256);
            $pos += 2 + $bytes;
        }
        return [$values, substr($data, $pos)];
    }

    /** Raw RSA decryption with MEGA's private key encoding (p, q, d, u). Returns big-endian bytes. */
    public static function rsaDecrypt(string $mpiCiphertext, string $privateKey): string
    {
        [[$c]] = self::readMpis($mpiCiphertext, 1);
        [[$p, $q, $d]] = self::readMpis($privateKey, 4);
        return $c->modPow($d, $p->multiply($q))->toBytes();
    }

    public static function randomKey(int $bytes = 16): string
    {
        return random_bytes($bytes);
    }

    private static function openssl(string $op, string $cipher, string $key, string $data, string $iv): string
    {
        if ($data === '') {
            return '';
        }
        if (strlen($data) % 16 !== 0) {
            throw new MegaException('AES input is not block aligned');
        }
        $out = $op === 'encrypt'
            ? openssl_encrypt($data, $cipher, $key, self::RAW, $iv)
            : openssl_decrypt($data, $cipher, $key, self::RAW, $iv);
        if ($out === false) {
            throw new MegaException("AES {$op} failure");
        }
        return $out;
    }
}
