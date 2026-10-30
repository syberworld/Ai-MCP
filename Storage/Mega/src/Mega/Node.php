<?php

declare(strict_types=1);

namespace AiMcp\Mega;

/** A decrypted MEGA filesystem node. */
final class Node
{
    public const FILE = 0;
    public const FOLDER = 1;
    public const ROOT = 2;
    public const INBOX = 3;
    public const TRASH = 4;

    public ?Node $parent = null;
    /** @var Node[] */
    public array $children = [];
    public ?string $key = null;
    public array $attributes = [];
    public ?string $publicHandle = null;
    /** Access level for incoming share roots: 0 read-only, 1 read/write, 2 full. */
    public ?int $access = null;
    public bool $incomingShare = false;

    public function __construct(
        public readonly string $handle,
        public readonly ?string $parentHandle,
        public readonly int $type,
        public readonly ?int $size,
        public readonly ?int $timestamp,
        public readonly ?string $owner,
    ) {
    }

    public static function fromApi(array $n): self
    {
        return new self(
            (string) $n['h'],
            isset($n['p']) ? (string) $n['p'] : null,
            (int) $n['t'],
            isset($n['s']) ? (int) $n['s'] : null,
            isset($n['ts']) ? (int) $n['ts'] : null,
            isset($n['u']) ? (string) $n['u'] : null,
        );
    }

    public function isFolder(): bool
    {
        return $this->type !== self::FILE;
    }

    public function name(): string
    {
        return match ($this->type) {
            self::ROOT => 'Cloud Drive',
            self::INBOX => 'Inbox',
            self::TRASH => 'Rubbish Bin',
            default => (string) ($this->attributes['n'] ?? $this->handle),
        };
    }

    /** Key used for attributes and content (folded for files). */
    public function aesKey(): string
    {
        if ($this->key === null) {
            throw new MegaException("Missing decryption key for node {$this->handle}");
        }
        return Crypto::fileAesKey($this->key);
    }

    public function child(string $name): ?Node
    {
        foreach ($this->children as $child) {
            if ($child->name() === $name) {
                return $child;
            }
        }
        return null;
    }

    /** @return \Generator<Node> */
    public function descendants(): \Generator
    {
        foreach ($this->children as $child) {
            yield $child;
            if ($child->isFolder()) {
                yield from $child->descendants();
            }
        }
    }
}
