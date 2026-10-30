<?php

declare(strict_types=1);

namespace AiMcp\Mega;

/**
 * MEGA account client: login, node tree decryption and all file operations.
 *
 * Remote references accepted by resolve():
 *   "/" or "/a/b"           Cloud Drive
 *   "trash:/..."            Rubbish Bin
 *   "inbox:/..."            Inbox
 *   "shares:/<name>/..."    incoming shares
 *   "id:<handle>"           node by handle
 */
final class MegaClient
{
    private const LABELS = ['', 'red', 'orange', 'yellow', 'green', 'blue', 'purple', 'grey'];
    private const ACCOUNT_TYPES = [0 => 'Free', 1 => 'Pro I', 2 => 'Pro II', 3 => 'Pro III', 4 => 'Pro Lite', 100 => 'Business', 101 => 'Pro Flexi'];

    /** @var array{sid:string, master:string, privk:?string, user:string, email:string, name:?string}|null */
    private ?array $session = null;
    private bool $sessionFromCache = false;
    /** @var array<string, Node>|null */
    private ?array $nodes = null;
    /** @var array<string, string> share root handle => share key */
    private array $shareKeys = [];
    private ?Node $root = null;
    private ?Node $trash = null;
    private ?Node $inbox = null;

    public function __construct(
        private readonly ApiClient $api,
        private readonly SessionStore $store,
        private readonly ?string $email,
        private readonly ?string $password,
    ) {
    }

    // ------------------------------------------------------------------ session

    public function login(?string $email = null, ?string $password = null, ?string $mfaCode = null): array
    {
        $email = strtolower(trim((string) ($email ?? $this->email)));
        $password = (string) ($password ?? $this->password);
        if ($email === '' || $password === '') {
            throw new MegaException('MEGA credentials missing: configure mega.email / mega.password or call mega_login.');
        }

        $this->api->setSid(null);
        $pre = $this->api->request(['a' => 'us0', 'user' => $email]);
        if ((int) ($pre['v'] ?? 1) === 2) {
            $derived = hash_pbkdf2('sha512', $password, Crypto::b64decode((string) $pre['s']), 100000, 32, true);
            $passwordKey = substr($derived, 0, 16);
            $userHash = Crypto::b64encode(substr($derived, 16, 16));
        } else {
            $passwordKey = Crypto::prepareKey($password);
            $userHash = Crypto::stringHash($email, $passwordKey);
        }

        $command = ['a' => 'us', 'user' => $email, 'uh' => $userHash];
        if ($mfaCode !== null && $mfaCode !== '') {
            $command['mfa'] = $mfaCode;
        }
        try {
            $res = $this->api->request($command);
        } catch (MegaException $e) {
            if ($e->isApiError(-26)) {
                throw new MegaException('This account uses two-factor authentication: call mega_login with twoFactorCode.', -26);
            }
            if ($e->isApiError(-9)) {
                throw new MegaException('Login failed: wrong e-mail or password.', -9);
            }
            throw $e;
        }

        $master = Crypto::aesEcbDecrypt($passwordKey, Crypto::b64decode((string) $res['k']));
        $privk = null;
        if (isset($res['csid'])) {
            $privk = Crypto::aesEcbDecrypt($master, Crypto::b64decode((string) $res['privk']));
            $sid = Crypto::b64encode(substr(Crypto::rsaDecrypt(Crypto::b64decode((string) $res['csid']), $privk), 0, 43));
        } elseif (isset($res['tsid'])) {
            $tsid = Crypto::b64decode((string) $res['tsid']);
            if (Crypto::aesEcbEncrypt($master, substr($tsid, 0, 16)) !== substr($tsid, -16)) {
                throw new MegaException('Login failed: invalid password.');
            }
            $sid = (string) $res['tsid'];
        } else {
            throw new MegaException('Unexpected MEGA login response.');
        }

        $this->api->setSid($sid);
        $user = $this->api->request(['a' => 'ug']);
        $this->session = [
            'sid' => $sid,
            'master' => $master,
            'privk' => $privk,
            'user' => (string) $user['u'],
            'email' => (string) ($user['email'] ?? $email),
            'name' => isset($user['name']) ? (string) $user['name'] : null,
        ];
        $this->sessionFromCache = false;
        $this->nodes = null;
        $this->store->save([
            'sid' => $sid,
            'master' => Crypto::b64encode($master),
            'privk' => $privk === null ? null : Crypto::b64encode($privk),
            'user' => $this->session['user'],
            'email' => $this->session['email'],
            'name' => $this->session['name'],
        ]);
        return $this->whoami();
    }

    public function logout(): void
    {
        if ($this->session !== null || $this->restoreSession()) {
            try {
                $this->api->request(['a' => 'sml']);
            } catch (MegaException) {
                // session may already be invalid
            }
        }
        $this->store->clear();
        $this->session = null;
        $this->nodes = null;
        $this->api->setSid(null);
    }

    public function whoami(): array
    {
        $this->ensureSession();
        return ['email' => $this->session['email'], 'name' => $this->session['name'], 'user' => $this->session['user']];
    }

    private function restoreSession(): bool
    {
        $cached = $this->store->load();
        if (!isset($cached['sid'], $cached['master'], $cached['user'])) {
            return false;
        }
        $this->session = [
            'sid' => (string) $cached['sid'],
            'master' => Crypto::b64decode((string) $cached['master']),
            'privk' => isset($cached['privk']) ? Crypto::b64decode((string) $cached['privk']) : null,
            'user' => (string) $cached['user'],
            'email' => (string) ($cached['email'] ?? ''),
            'name' => $cached['name'] ?? null,
        ];
        $this->sessionFromCache = true;
        $this->api->setSid($this->session['sid']);
        return true;
    }

    private function ensureSession(): void
    {
        if ($this->session === null && !$this->restoreSession()) {
            $this->login();
        }
    }

    /** Authenticated API call; transparently re-logs in once if a cached session has expired. */
    private function call(array $command, array $query = []): mixed
    {
        $this->ensureSession();
        try {
            return $this->api->request($command, $query);
        } catch (MegaException $e) {
            if (!$e->isApiError(-15) || !$this->sessionFromCache) {
                throw $e;
            }
            $this->store->clear();
            $this->session = null;
            $this->login();
            return $this->api->request($command, $query);
        }
    }

    // ------------------------------------------------------------------ node tree

    /** @return array<string, Node> */
    private function tree(): array
    {
        if ($this->nodes === null) {
            $this->fetchNodes();
        }
        return $this->nodes;
    }

    public function reload(): int
    {
        $this->nodes = null;
        return count($this->tree());
    }

    private function fetchNodes(): void
    {
        $res = $this->call(['a' => 'f', 'c' => 1, 'r' => 1]);
        $master = $this->session['master'];
        $this->nodes = [];
        $this->shareKeys = [];
        $this->root = $this->trash = $this->inbox = null;

        foreach ($res['ok'] ?? [] as $share) {
            $h = (string) $share['h'];
            if (hash_equals(Crypto::aesEcbEncrypt($master, $h . $h), Crypto::b64decode((string) $share['ha']))) {
                $this->shareKeys[$h] = Crypto::aesEcbDecrypt($master, Crypto::b64decode((string) $share['k']));
            }
        }

        $raws = [];
        foreach ($res['f'] ?? [] as $raw) {
            $node = Node::fromApi($raw);
            if (isset($raw['sk'])) {
                $this->shareKeys[$node->handle] = $this->decryptShareKey((string) $raw['sk']);
                $node->incomingShare = isset($raw['su']);
                $node->access = isset($raw['r']) ? (int) $raw['r'] : null;
            }
            $this->nodes[$node->handle] = $node;
            $raws[$node->handle] = $raw;
        }

        $user = $this->session['user'];
        $lookup = fn (string $id): ?string => $id === $user ? $master : ($this->shareKeys[$id] ?? null);
        foreach ($this->nodes as $handle => $node) {
            self::decryptNode($node, $raws[$handle], $lookup);
        }
        self::link($this->nodes);

        foreach ($this->nodes as $node) {
            match ($node->type) {
                Node::ROOT => $this->root = $node,
                Node::TRASH => $this->trash = $node,
                Node::INBOX => $this->inbox = $node,
                default => null,
            };
        }
        foreach ($res['ph'] ?? [] as $ph) {
            if (isset($this->nodes[$ph['h']])) {
                $this->nodes[$ph['h']]->publicHandle = (string) $ph['ph'];
            }
        }
    }

    private function decryptShareKey(string $sk): string
    {
        $bin = Crypto::b64decode($sk);
        if (strlen($bin) > 16) {
            if ($this->session['privk'] === null) {
                throw new MegaException('Cannot decrypt RSA share key without private key');
            }
            return substr(Crypto::rsaDecrypt($bin, $this->session['privk']), 0, 16);
        }
        return Crypto::aesEcbDecrypt($this->session['master'], $bin);
    }

    /** @param callable(string): ?string $keyFor returns the AES key that wraps node keys for a given id */
    private static function decryptNode(Node $node, array $raw, callable $keyFor): void
    {
        if (!isset($raw['k'], $raw['a']) || !is_string($raw['k'])) {
            return;
        }
        foreach (explode('/', $raw['k']) as $pair) {
            $pos = strpos($pair, ':');
            if ($pos === false) {
                continue;
            }
            $wrapKey = $keyFor(substr($pair, 0, $pos));
            $encrypted = Crypto::b64decode(substr($pair, $pos + 1));
            if ($wrapKey === null || !in_array(strlen($encrypted), [16, 32], true)) {
                continue;
            }
            $node->key = Crypto::aesEcbDecrypt($wrapKey, $encrypted);
            break;
        }
        if ($node->key !== null) {
            $node->attributes = Crypto::decryptAttributes((string) $raw['a'], $node->aesKey()) ?? [];
        }
    }

    /** @param array<string, Node> $nodes */
    private static function link(array $nodes): void
    {
        foreach ($nodes as $node) {
            if ($node->parentHandle !== null && isset($nodes[$node->parentHandle]) && $node->parent === null) {
                $node->parent = $nodes[$node->parentHandle];
                $node->parent->children[] = $node;
            }
        }
    }

    /** @return Node[] */
    public function incomingShares(): array
    {
        return array_values(array_filter($this->tree(), fn (Node $n) => $n->incomingShare && $n->parent === null));
    }

    /** @return Node[] own nodes exported with a public link */
    public function publicLinks(): array
    {
        return array_values(array_filter($this->tree(), fn (Node $n) => $n->publicHandle !== null));
    }

    public function resolve(string $ref): Node
    {
        $nodes = $this->tree();
        $ref = trim($ref);
        if (str_starts_with($ref, 'id:')) {
            $handle = substr($ref, 3);
            return $nodes[$handle] ?? throw new MegaException("No node with id \"{$handle}\"");
        }
        if (!preg_match('/^(trash|inbox|shares|drive):(.*)$/is', $ref, $m)) {
            $m = [$ref, 'drive', $ref];
        }
        $parts = self::splitPath($m[2]);
        $base = match (strtolower($m[1])) {
            'trash' => $this->trash,
            'inbox' => $this->inbox,
            'shares' => $this->shareByName(array_shift($parts) ?? ''),
            default => $this->root,
        };
        if ($base === null) {
            throw new MegaException("Location for \"{$ref}\" is not available");
        }
        return self::walk($base, $parts, $ref);
    }

    private function shareByName(string $name): Node
    {
        if ($name === '') {
            throw new MegaException('Specify a share name, e.g. "shares:/ShareName/sub"');
        }
        foreach ($this->incomingShares() as $share) {
            if ($share->name() === $name) {
                return $share;
            }
        }
        throw new MegaException("Incoming share \"{$name}\" not found");
    }

    /** @return string[] */
    private static function splitPath(string $path): array
    {
        return array_values(array_filter(explode('/', $path), fn ($p) => $p !== '' && $p !== '.'));
    }

    private static function walk(Node $node, array $parts, string $ref): Node
    {
        foreach ($parts as $part) {
            if ($part === '..') {
                $node = $node->parent ?? throw new MegaException("Path \"{$ref}\" goes above its root");
                continue;
            }
            $node = $node->child($part) ?? throw new MegaException("Path not found: \"{$ref}\" (missing \"{$part}\")");
        }
        return $node;
    }

    /** Resolves a folder, creating missing path components (mkdir -p). */
    public function ensureFolder(string $ref): Node
    {
        $this->tree();
        if (str_starts_with(trim($ref), 'id:')) {
            return $this->requireFolder($this->resolve($ref));
        }
        if (!preg_match('/^(trash|inbox|shares|drive):(.*)$/is', trim($ref), $m)) {
            $m = [$ref, 'drive', $ref];
        }
        $parts = self::splitPath($m[2]);
        $prefix = strtolower($m[1]);
        $node = $prefix === 'shares'
            ? $this->shareByName(array_shift($parts) ?? '')
            : $this->resolve($prefix . ':/');
        foreach ($parts as $part) {
            $existing = $part === '..' ? $node->parent : $node->child($part);
            $node = $existing !== null ? $this->requireFolder($existing) : $this->mkdir($node, $part);
        }
        return $node;
    }

    public function requireFolder(Node $node): Node
    {
        if (!$node->isFolder()) {
            throw new MegaException("\"{$node->name()}\" is a file, not a folder");
        }
        return $node;
    }

    /** Splits "/a/b/c" into ["/a/b", "c"], keeping any scope prefix. */
    public static function splitParent(string $ref): array
    {
        preg_match('/^((?:trash|inbox|shares|drive):)?(.*)$/is', trim($ref), $m);
        $parts = self::splitPath($m[2]);
        $name = array_pop($parts);
        if ($name === null) {
            throw new MegaException("\"{$ref}\" has no final name component");
        }
        return [($m[1] ?? '') . '/' . implode('/', $parts), $name];
    }

    public function pathOf(Node $node): string
    {
        $names = [];
        $top = $node;
        for ($cur = $node; $cur !== null; $cur = $cur->parent) {
            $top = $cur;
            if ($cur->parent !== null) {
                array_unshift($names, $cur->name());
            }
        }
        $prefix = match (true) {
            $top === $this->root => '',
            $top === $this->trash => 'trash:',
            $top === $this->inbox => 'inbox:',
            default => 'shares:',
        };
        if ($prefix === 'shares:') {
            array_unshift($names, $top->name());
        }
        return $prefix . '/' . implode('/', $names);
    }

    public function describe(Node $node, bool $withPath = true): array
    {
        $out = ['name' => $node->name(), 'id' => $node->handle, 'type' => $node->isFolder() ? 'folder' : 'file'];
        if ($withPath) {
            $out['path'] = $this->pathOf($node);
        }
        if (!$node->isFolder()) {
            $out['size'] = $node->size;
        } else {
            $out['childCount'] = count($node->children);
        }
        if ($node->timestamp) {
            $out['modified'] = gmdate('c', $node->timestamp);
        }
        if (!empty($node->attributes['lbl'])) {
            $out['label'] = self::LABELS[(int) $node->attributes['lbl']] ?? $node->attributes['lbl'];
        }
        if (!empty($node->attributes['fav'])) {
            $out['favorite'] = true;
        }
        if ($node->publicHandle !== null) {
            $out['publicLink'] = true;
        }
        if ($node->access !== null) {
            $out['access'] = ['read-only', 'read-write', 'full'][$node->access] ?? $node->access;
        }
        if ($node->key === null) {
            $out['undecryptable'] = true;
        }
        return $out;
    }

    // ------------------------------------------------------------------ write operations

    private function encryptKey(string $key): string
    {
        return Crypto::b64encode(Crypto::aesEcbEncrypt($this->session['master'], $key));
    }

    /**
     * Adds the "cr" share-key block so that nodes created inside a shared folder stay readable
     * by the other members of the share.
     * @param array<array{0:string,1:string}> $handleKeys list of [handle, node key]
     */
    private function addCryptoRequest(array &$command, Node $target, array $handleKeys): void
    {
        $shares = [];
        for ($n = $target; $n !== null; $n = $n->parent) {
            if (isset($this->shareKeys[$n->handle])) {
                $shares[] = $n->handle;
            }
        }
        if ($shares === [] || $handleKeys === []) {
            return;
        }
        $triples = [];
        foreach ($shares as $si => $shareHandle) {
            foreach ($handleKeys as $ni => [, $key]) {
                array_push($triples, $si, $ni, Crypto::b64encode(Crypto::aesEcbEncrypt($this->shareKeys[$shareHandle], $key)));
            }
        }
        $command['cr'] = [$shares, array_column($handleKeys, 0), $triples];
    }

    /** @return Node[] */
    private function putNodes(array $command, array $query = []): array
    {
        $res = $this->call($command, $query);
        $user = $this->session['user'];
        $master = $this->session['master'];
        $lookup = fn (string $id): ?string => $id === $user ? $master : ($this->shareKeys[$id] ?? null);
        $created = [];
        foreach ($res['f'] ?? [] as $raw) {
            $node = Node::fromApi($raw);
            self::decryptNode($node, $raw, $lookup);
            $this->nodes[$node->handle] = $node;
            $created[] = $node;
        }
        self::link($this->nodes);
        return $created;
    }

    public function mkdir(Node $parent, string $name): Node
    {
        $this->requireFolder($parent);
        $key = Crypto::randomKey();
        $command = ['a' => 'p', 't' => $parent->handle, 'n' => [[
            'h' => 'xxxxxxxx',
            't' => Node::FOLDER,
            'a' => Crypto::encryptAttributes(['n' => $name], $key),
            'k' => $this->encryptKey($key),
        ]]];
        $this->addCryptoRequest($command, $parent, [['xxxxxxxx', $key]]);
        return $this->putNodes($command)[0];
    }

    public function setAttributes(Node $node, array $changes): void
    {
        $attrs = $node->attributes;
        foreach ($changes as $k => $v) {
            if ($v === null) {
                unset($attrs[$k]);
            } else {
                $attrs[$k] = $v;
            }
        }
        $this->call(['a' => 'a', 'n' => $node->handle, 'at' => Crypto::encryptAttributes($attrs, $node->aesKey())]);
        $node->attributes = $attrs;
    }

    public function rename(Node $node, string $name): void
    {
        $this->guardSpecial($node);
        $this->setAttributes($node, ['n' => $name]);
    }

    public function setLabel(Node $node, string $label): void
    {
        $index = array_search($label, self::LABELS, true);
        $this->setAttributes($node, ['lbl' => $index ?: null]);
    }

    public function setFavorite(Node $node, bool $favorite): void
    {
        $this->setAttributes($node, ['fav' => $favorite ? 1 : null]);
    }

    public function move(Node $node, Node $target): void
    {
        $this->guardSpecial($node);
        $this->requireFolder($target);
        for ($n = $target; $n !== null; $n = $n->parent) {
            if ($n === $node) {
                throw new MegaException('Cannot move a folder into itself');
            }
        }
        $this->call(['a' => 'm', 'n' => $node->handle, 't' => $target->handle]);
        if ($node->parent !== null) {
            $node->parent->children = array_values(array_filter($node->parent->children, fn ($c) => $c !== $node));
        }
        $node->parent = $target;
        $target->children[] = $node;
    }

    /** Server-side copy of a node (recursively for folders). */
    public function copy(Node $node, Node $target): Node
    {
        $this->guardSpecial($node);
        $this->requireFolder($target);
        $items = [];
        $handleKeys = [];
        $add = function (Node $n, ?string $parent) use (&$add, &$items, &$handleKeys): void {
            if ($n->key === null) {
                throw new MegaException("Cannot copy \"{$n->name()}\": missing key");
            }
            $attrs = $n->attributes;
            unset($attrs['rr']);
            $item = [
                'h' => $n->handle,
                't' => $n->isFolder() ? Node::FOLDER : Node::FILE,
                'a' => Crypto::encryptAttributes($attrs, $n->aesKey()),
                'k' => $this->encryptKey($n->key),
            ];
            if ($parent !== null) {
                $item['p'] = $parent;
            }
            $items[] = $item;
            $handleKeys[] = [$n->handle, $n->key];
            foreach ($n->children as $child) {
                $add($child, $n->handle);
            }
        };
        $add($node, null);
        $command = ['a' => 'p', 't' => $target->handle, 'n' => $items];
        $this->addCryptoRequest($command, $target, $handleKeys);
        return $this->putNodes($command)[0];
    }

    public function delete(Node $node, bool $permanent): void
    {
        $this->guardSpecial($node);
        if (!$permanent && !$this->isInTrash($node)) {
            if ($node->parent !== null && $node->key !== null) {
                $this->setAttributes($node, ['rr' => $node->parent->handle]);
            }
            $this->move($node, $this->trash ?? throw new MegaException('Rubbish Bin not available'));
            return;
        }
        $this->call(['a' => 'd', 'n' => $node->handle]);
        $this->forget($node);
    }

    /** Moves a node out of the Rubbish Bin, to its original folder when known. */
    public function restore(Node $node, ?Node $target = null): Node
    {
        if (!$this->isInTrash($node)) {
            throw new MegaException("\"{$node->name()}\" is not in the Rubbish Bin");
        }
        if ($target === null) {
            $original = $this->nodes[$node->attributes['rr'] ?? ''] ?? null;
            $target = ($original !== null && !$this->isInTrash($original)) ? $original : $this->root;
        }
        $this->move($node, $target);
        if (isset($node->attributes['rr'])) {
            $this->setAttributes($node, ['rr' => null]);
        }
        return $target;
    }

    public function emptyTrash(): int
    {
        $this->tree();
        $count = 0;
        foreach ($this->trash?->children ?? [] as $child) {
            $this->call(['a' => 'd', 'n' => $child->handle]);
            $this->forget($child);
            $count++;
        }
        return $count;
    }

    public function isInTrash(Node $node): bool
    {
        for ($n = $node; $n !== null; $n = $n->parent) {
            if ($n->type === Node::TRASH) {
                return true;
            }
        }
        return false;
    }

    private function guardSpecial(Node $node): void
    {
        if (in_array($node->type, [Node::ROOT, Node::TRASH, Node::INBOX], true)) {
            throw new MegaException('This operation is not allowed on a root folder');
        }
    }

    private function forget(Node $node): void
    {
        foreach (iterator_to_array($node->descendants(), false) as $d) {
            unset($this->nodes[$d->handle]);
        }
        unset($this->nodes[$node->handle]);
        if ($node->parent !== null) {
            $node->parent->children = array_values(array_filter($node->parent->children, fn ($c) => $c !== $node));
        }
    }

    // ------------------------------------------------------------------ sharing

    public function createLink(Node $node, bool $includeKey): array
    {
        $this->guardSpecial($node);
        if ($node->key === null) {
            throw new MegaException('Missing node key');
        }
        if ($node->isFolder()) {
            if (!isset($this->shareKeys[$node->handle])) {
                $this->exportFolder($node);
            }
            $key = $this->shareKeys[$node->handle];
        } else {
            $key = $node->key;
        }
        $ph = (string) $this->call(['a' => 'l', 'n' => $node->handle]);
        $node->publicHandle = $ph;
        $url = 'https://mega.nz/' . ($node->isFolder() ? 'folder' : 'file') . '/' . $ph;
        $encodedKey = Crypto::b64encode($key);
        return ['url' => $includeKey ? "{$url}#{$encodedKey}" : $url, 'key' => $encodedKey];
    }

    private function exportFolder(Node $node): void
    {
        $shareKey = Crypto::randomKey();
        $handleKeys = [[$node->handle, $node->key]];
        foreach ($node->descendants() as $d) {
            if ($d->key !== null) {
                $handleKeys[] = [$d->handle, $d->key];
            }
        }
        $triples = [];
        foreach ($handleKeys as $i => [, $key]) {
            array_push($triples, 0, $i, Crypto::b64encode(Crypto::aesEcbEncrypt($shareKey, $key)));
        }
        $h = $node->handle;
        $this->call([
            'a' => 's2',
            'n' => $h,
            's' => [['u' => 'EXP', 'r' => 0]],
            'ok' => Crypto::b64encode(Crypto::aesEcbEncrypt($this->session['master'], $shareKey)),
            'ha' => Crypto::b64encode(Crypto::aesEcbEncrypt($this->session['master'], $h . $h)),
            'cr' => [[$h], array_column($handleKeys, 0), $triples],
        ]);
        $this->shareKeys[$h] = $shareKey;
    }

    public function removeLink(Node $node): void
    {
        $this->call(['a' => 'l', 'n' => $node->handle, 'd' => 1]);
        if ($node->isFolder()) {
            try {
                $this->call(['a' => 's2', 'n' => $node->handle, 's' => [['u' => 'EXP', 'r' => '']]]);
            } catch (MegaException) {
                // no EXP share left to remove
            }
        }
        $node->publicHandle = null;
    }

    public function accountInfo(): array
    {
        $q = $this->call(['a' => 'uq', 'strg' => 1, 'xfer' => 1, 'pro' => 1]);
        $type = (int) ($q['utype'] ?? 0);
        return [
            'accountType' => self::ACCOUNT_TYPES[$type] ?? "type {$type}",
            'spaceUsed' => (int) ($q['cstrg'] ?? 0),
            'spaceTotal' => (int) ($q['mstrg'] ?? 0),
            'transferUsed' => (int) ($q['caxfer'] ?? 0) + (int) ($q['csxfer'] ?? 0),
            'transferTotal' => (int) ($q['mxfer'] ?? 0),
            'proExpiresAt' => !empty($q['suntil']) ? gmdate('c', (int) $q['suntil']) : null,
        ];
    }

    // ------------------------------------------------------------------ transfers

    /** Returns up to $length decrypted bytes starting at $start. */
    public function read(Node $node, int $start, int $length): string
    {
        if ($node->isFolder()) {
            throw new MegaException("\"{$node->name()}\" is a folder");
        }
        return $this->readContent(['a' => 'g', 'g' => 1, 'n' => $node->handle, 'ssl' => 2], [], false, (string) $node->key, $start, $length);
    }

    private function readContent(array $command, array $query, bool $anonymous, string $key, int $start, int $length): string
    {
        if (strlen($key) !== 32) {
            throw new MegaException('Missing or invalid file key');
        }
        $info = $anonymous ? $this->api->request($command, $query, true) : $this->call($command, $query);
        if (isset($info['e']) && is_int($info['e']) && $info['e'] < 0) {
            throw MegaException::fromApiCode($info['e']);
        }
        $url = is_array($info['g'] ?? null) ? $info['g'][0] : ($info['g'] ?? null);
        if (!is_string($url) || $url === '') {
            throw new MegaException('Download URL not available');
        }
        $size = (int) $info['s'];
        if ($length <= 0 || $start >= $size) {
            return '';
        }
        $end = min($size, $start + $length) - 1;
        $aligned = $start - $start % 16;
        $encrypted = $this->api->get("{$url}/{$aligned}-{$end}");
        $plain = Crypto::aesCtr(Crypto::fileAesKey($key), substr($key, 16, 8), $aligned, $encrypted);
        return substr($plain, $start - $aligned);
    }

    /**
     * Uploads $size bytes read from $stream as a new file.
     * @param resource $stream
     */
    public function upload(Node $folder, string $name, $stream, int $size): Node
    {
        $this->requireFolder($folder);
        $ul = $this->call(['a' => 'u', 's' => $size, 'ssl' => 2]);
        $url = (string) $ul['p'];
        $key = Crypto::randomKey();
        $nonce = Crypto::randomKey(8);
        $macs = '';
        $token = $size === 0 ? $this->api->post("{$url}/0", '') : '';
        foreach (Crypto::chunks($size) as $offset => $length) {
            $chunk = '';
            while (strlen($chunk) < $length && !feof($stream)) {
                $chunk .= (string) fread($stream, $length - strlen($chunk));
            }
            if (strlen($chunk) !== $length) {
                throw new MegaException('Upload source ended early');
            }
            $macs .= Crypto::chunkMac($key, $nonce, $chunk);
            $token = $this->api->post("{$url}/{$offset}", Crypto::aesCtr($key, $nonce, $offset, $chunk));
        }
        if ($token === '' || preg_match('/^-\d+$/', $token)) {
            throw $token === '' ? new MegaException('Upload failed: no completion token') : MegaException::fromApiCode((int) $token);
        }
        $metaMac = Crypto::metaMac($key, $macs);
        $fileKey = ($key ^ ($nonce . $metaMac)) . $nonce . $metaMac;
        $command = ['a' => 'p', 't' => $folder->handle, 'n' => [[
            'h' => $token,
            't' => Node::FILE,
            'a' => Crypto::encryptAttributes(['n' => $name], $key),
            'k' => $this->encryptKey($fileKey),
        ]]];
        $this->addCryptoRequest($command, $folder, [[$token, $fileKey]]);
        return $this->putNodes($command)[0];
    }

    public function uploadString(Node $folder, string $name, string $data): Node
    {
        $stream = fopen('php://temp', 'w+b');
        fwrite($stream, $data);
        rewind($stream);
        try {
            return $this->upload($folder, $name, $stream, strlen($data));
        } finally {
            fclose($stream);
        }
    }

    // ------------------------------------------------------------------ public links

    /** @return array{type:string, handle:string, key:string, sub:?string} */
    public static function parseLink(string $url): array
    {
        $url = trim($url);
        if (preg_match('~/(file|folder)/([\w-]{8})#([\w-]+)(?:/(?:file|folder)/([\w-]{8}))?~', $url, $m)) {
            return ['type' => $m[1], 'handle' => $m[2], 'key' => $m[3], 'sub' => $m[4] ?? null];
        }
        if (preg_match('~#(F?)!([\w-]{8})!([\w-]+)(?:!([\w-]{8}))?~', $url, $m)) {
            return ['type' => $m[1] === 'F' ? 'folder' : 'file', 'handle' => $m[2], 'key' => $m[3], 'sub' => $m[4] ?? null];
        }
        throw new MegaException('Unrecognised MEGA link (expected https://mega.nz/file/<id>#<key> or /folder/<id>#<key>)');
    }

    /**
     * Loads a public link without logging in.
     * @return array{link:array, root:Node, target:Node}
     */
    public function openPublic(string $url, ?string $subPath = null): array
    {
        $link = self::parseLink($url);
        $key = Crypto::b64decode($link['key']);
        if ($link['type'] === 'file') {
            if (strlen($key) !== 32) {
                throw new MegaException('Invalid file key in link');
            }
            $info = $this->api->request(['a' => 'g', 'p' => $link['handle'], 'ssl' => 2], [], true);
            $node = new Node($link['handle'], null, Node::FILE, (int) $info['s'], null, null);
            $node->key = $key;
            $node->attributes = Crypto::decryptAttributes((string) $info['at'], $node->aesKey())
                ?? throw new MegaException('Wrong decryption key for this link');
            return ['link' => $link, 'root' => $node, 'target' => $node];
        }

        $res = $this->api->request(['a' => 'f', 'c' => 1, 'ca' => 1, 'r' => 1], ['n' => $link['handle']], true);
        $nodes = [];
        foreach ($res['f'] ?? [] as $raw) {
            $node = Node::fromApi($raw);
            self::decryptNode($node, $raw, fn () => $key);
            $nodes[$node->handle] = $node;
        }
        self::link($nodes);
        $root = null;
        foreach ($nodes as $node) {
            if ($node->parent === null) {
                $root = $node;
                break;
            }
        }
        if ($root === null) {
            throw new MegaException('Empty or invalid folder link');
        }
        if ($root->key === null || $root->attributes === []) {
            throw new MegaException('Wrong decryption key for this link');
        }
        $target = $link['sub'] !== null ? ($nodes[$link['sub']] ?? $root) : $root;
        $target = self::walk($target, self::splitPath((string) $subPath), (string) $subPath);
        return ['link' => $link, 'root' => $root, 'target' => $target];
    }

    public function readPublic(array $opened, Node $node, int $start, int $length): string
    {
        if ($node->isFolder()) {
            throw new MegaException("\"{$node->name()}\" is a folder");
        }
        $link = $opened['link'];
        if ($link['type'] === 'file') {
            return $this->readContent(['a' => 'g', 'g' => 1, 'p' => $link['handle'], 'ssl' => 2], [], true, (string) $node->key, $start, $length);
        }
        return $this->readContent(['a' => 'g', 'g' => 1, 'n' => $node->handle, 'ssl' => 2], ['n' => $link['handle']], true, (string) $node->key, $start, $length);
    }

    /** Imports a public file or folder link into the account. Returns the created top node. */
    public function importLink(string $url, Node $target): Node
    {
        $this->requireFolder($target);
        $opened = $this->openPublic($url);
        $source = $opened['target'];
        $link = $opened['link'];
        $this->tree();

        if ($link['type'] === 'file') {
            $command = ['a' => 'p', 't' => $target->handle, 'n' => [[
                'ph' => $link['handle'],
                't' => Node::FILE,
                'a' => Crypto::encryptAttributes($source->attributes, $source->aesKey()),
                'k' => $this->encryptKey((string) $source->key),
            ]]];
            $this->addCryptoRequest($command, $target, [[$link['handle'], (string) $source->key]]);
            return $this->putNodes($command)[0];
        }

        // Folder link: server-side copy of the whole subtree, authorised by the folder handle.
        $items = [];
        $handleKeys = [];
        $add = function (Node $n, ?string $parent) use (&$add, &$items, &$handleKeys): void {
            if ($n->key === null) {
                return;
            }
            $item = [
                'h' => $n->handle,
                't' => $n->isFolder() ? Node::FOLDER : Node::FILE,
                'a' => Crypto::encryptAttributes($n->attributes, $n->aesKey()),
                'k' => $this->encryptKey($n->key),
            ];
            if ($parent !== null) {
                $item['p'] = $parent;
            }
            $items[] = $item;
            $handleKeys[] = [$n->handle, $n->key];
            foreach ($n->children as $child) {
                $add($child, $n->handle);
            }
        };
        $add($source, null);
        $command = ['a' => 'p', 't' => $target->handle, 'n' => $items];
        $this->addCryptoRequest($command, $target, $handleKeys);
        return $this->putNodes($command, ['n' => $link['handle']])[0]
            ?? throw new MegaException('Import returned no nodes');
    }

    /** Raw API access with the current session. */
    public function rawRequest(array $command): mixed
    {
        return $this->call($command);
    }
}
