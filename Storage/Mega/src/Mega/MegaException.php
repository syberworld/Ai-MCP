<?php

declare(strict_types=1);

namespace AiMcp\Mega;

final class MegaException extends \RuntimeException
{
    private const API_ERRORS = [
        -1 => 'EINTERNAL: internal error',
        -2 => 'EARGS: invalid arguments',
        -3 => 'EAGAIN: temporary congestion, try again',
        -4 => 'ERATELIMIT: rate limit exceeded',
        -5 => 'EFAILED: request failed',
        -6 => 'ETOOMANY: too many requests or concurrent IPs',
        -7 => 'ERANGE: resource out of range',
        -8 => 'EEXPIRED: resource expired',
        -9 => 'ENOENT: resource does not exist',
        -10 => 'ECIRCULAR: circular linkage',
        -11 => 'EACCESS: access denied',
        -12 => 'EEXIST: resource already exists',
        -13 => 'EINCOMPLETE: request incomplete',
        -14 => 'EKEY: cryptographic error (invalid key?)',
        -15 => 'ESID: invalid or expired session',
        -16 => 'EBLOCKED: resource administratively blocked',
        -17 => 'EOVERQUOTA: quota exceeded',
        -18 => 'ETEMPUNAVAIL: resource temporarily unavailable',
        -19 => 'ETOOMANYCONNECTIONS: too many connections',
        -24 => 'EGOINGOVERQUOTA: operation would exceed quota',
        -26 => 'EMFAREQUIRED: two-factor authentication code required',
    ];

    public static function fromApiCode(int $code): self
    {
        $message = self::API_ERRORS[$code] ?? "unknown MEGA API error";
        return new self("MEGA API error {$code} ({$message})", $code);
    }

    public function isApiError(int $code): bool
    {
        return $this->getCode() === $code;
    }
}
