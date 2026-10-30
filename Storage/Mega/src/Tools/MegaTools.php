<?php

declare(strict_types=1);

namespace AiMcp\Tools;

use AiMcp\Mcp\ToolRegistry;
use AiMcp\Mega\MegaClient;
use AiMcp\Mega\MegaException;
use AiMcp\Mega\Node;

/** Registers the MEGA tools exposed over MCP. */
final class MegaTools
{
    private const PATH_HELP = 'Remote path. "/" is the Cloud Drive root ("/Docs/a.txt"); use "trash:/..." for the Rubbish Bin, '
        . '"inbox:/..." for the Inbox, "shares:/<ShareName>/..." for incoming shares, or "id:<handle>" to address a node by id.';

    public function __construct(
        private readonly MegaClient $mega,
        private readonly int $maxReadBytes,
        private readonly int $maxUploadBytes,
    ) {
    }

    public function register(ToolRegistry $r): void
    {
        $path = ['type' => 'string', 'description' => self::PATH_HELP];
        $folder = fn (string $desc, ?string $default = null) => ['type' => 'string', 'description' => $desc . ' ' . self::PATH_HELP]
            + ($default !== null ? ['default' => $default] : []);
        $destructive = ['destructiveHint' => true];
        $readOnly = ['readOnlyHint' => true];

        // -------------------------------------------------------------- account
        $r->add('mega_login', 'Login to MEGA',
            'Log in to MEGA (or switch account / supply a 2FA code). Without arguments uses the configured credentials. '
            . 'Other tools log in automatically; the session is cached on the server.',
            [
                'email' => ['type' => 'string'],
                'password' => ['type' => 'string'],
                'twoFactorCode' => ['type' => 'string', 'description' => 'Current 6-digit 2FA code if the account has 2FA'],
            ], [],
            fn ($a) => ['loggedIn' => true] + $this->mega->login($a['email'], $a['password'], $a['twoFactorCode']));

        $r->add('mega_logout', 'Logout', 'Terminate the cached MEGA session.', [], [],
            function () {
                $this->mega->logout();
                return ['loggedIn' => false];
            });

        $r->add('mega_account_info', 'Account info', 'Account type, storage quota and transfer quota.', [], [],
            function () {
                $info = $this->mega->whoami() + $this->mega->accountInfo();
                $info['spaceFree'] = $info['spaceTotal'] - $info['spaceUsed'];
                foreach (['spaceUsed', 'spaceTotal', 'spaceFree', 'transferUsed', 'transferTotal'] as $k) {
                    $info[$k . 'Human'] = self::bytes($info[$k]);
                }
                return $info;
            }, $readOnly);

        $r->add('mega_reload', 'Reload file tree', 'Re-fetch the file tree from MEGA.', [], [],
            fn () => ['reloaded' => true, 'nodes' => $this->mega->reload()], $readOnly);

        // -------------------------------------------------------------- browse
        $r->add('mega_list', 'List folder', 'List the contents of a folder, optionally recursively.',
            [
                'path' => $path + ['default' => '/'],
                'recursive' => ['type' => 'boolean', 'default' => false],
                'maxDepth' => ['type' => 'integer', 'default' => 10, 'minimum' => 0, 'maximum' => 50],
                'limit' => ['type' => 'integer', 'default' => 500, 'minimum' => 1, 'maximum' => 10000],
            ], [],
            function ($a) {
                $node = $this->mega->requireFolder($this->mega->resolve($a['path']));
                $entries = [];
                $this->listTree($node, 0, $a['recursive'] ? $a['maxDepth'] : 0, $entries, $a['limit'], true);
                return ['folder' => $this->mega->describe($node), 'entries' => $entries, 'truncated' => count($entries) >= $a['limit']];
            }, $readOnly);

        $r->add('mega_get_info', 'Get node info', 'Metadata of a file or folder.', ['path' => $path], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                return $this->mega->describe($node) + ['attributes' => $node->attributes];
            }, $readOnly);

        $r->add('mega_search', 'Search', 'Find files/folders by name (case-insensitive substring, or regular expression) under a folder.',
            [
                'query' => ['type' => 'string'],
                'regex' => ['type' => 'boolean', 'default' => false],
                'path' => $folder('Folder to search recursively.', '/'),
                'type' => ['type' => 'string', 'enum' => ['any', 'file', 'folder'], 'default' => 'any'],
                'limit' => ['type' => 'integer', 'default' => 200, 'minimum' => 1, 'maximum' => 5000],
            ], ['query'],
            function ($a) {
                $base = $this->mega->requireFolder($this->mega->resolve($a['path']));
                $pattern = $a['regex'] ? '~' . str_replace('~', '\~', $a['query']) . '~iu' : null;
                if ($pattern !== null && @preg_match($pattern, '') === false) {
                    throw new MegaException('Invalid regular expression');
                }
                $results = [];
                foreach ($base->descendants() as $node) {
                    if (count($results) >= $a['limit']) {
                        break;
                    }
                    if (($a['type'] === 'file' && $node->isFolder()) || ($a['type'] === 'folder' && !$node->isFolder())) {
                        continue;
                    }
                    $name = $node->name();
                    if ($pattern !== null ? preg_match($pattern, $name) : mb_stripos($name, $a['query']) !== false) {
                        $results[] = $this->mega->describe($node);
                    }
                }
                return ['count' => count($results), 'results' => $results];
            }, $readOnly);

        $r->add('mega_list_shares', 'List shares', 'Incoming shares (folders shared with you) and your nodes exported with a public link.', [], [],
            fn () => [
                'incoming' => array_map(fn (Node $n) => $this->mega->describe($n), $this->mega->incomingShares()),
                'publicLinks' => array_map(fn (Node $n) => $this->mega->describe($n), $this->mega->publicLinks()),
            ], $readOnly);

        // -------------------------------------------------------------- modify
        $r->add('mega_mkdir', 'Create folder', 'Create a folder; missing parent folders are created too.', ['path' => $path], ['path'],
            fn ($a) => $this->mega->describe($this->mega->ensureFolder($a['path'])));

        $r->add('mega_rename', 'Rename', 'Rename a file or folder.', ['path' => $path, 'newName' => ['type' => 'string']], ['path', 'newName'],
            function ($a) {
                if (trim($a['newName']) === '' || str_contains($a['newName'], '/')) {
                    throw new MegaException('Invalid name');
                }
                $node = $this->mega->resolve($a['path']);
                $this->mega->rename($node, $a['newName']);
                return $this->mega->describe($node);
            });

        $r->add('mega_move', 'Move', 'Move a file or folder into another folder.',
            ['path' => $path, 'destination' => $folder('Destination folder.')], ['path', 'destination'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $this->mega->move($node, $this->mega->resolve($a['destination']));
                return ['moved' => true] + $this->mega->describe($node);
            });

        $r->add('mega_copy', 'Copy', 'Server-side copy of a file or folder into another folder.',
            ['path' => $path, 'destination' => $folder('Destination folder.')], ['path', 'destination'],
            fn ($a) => ['copied' => true] + $this->mega->describe(
                $this->mega->copy($this->mega->resolve($a['path']), $this->mega->resolve($a['destination']))
            ));

        $r->add('mega_delete', 'Delete', 'Delete a file or folder: moved to the Rubbish Bin, or removed forever with permanent=true (always permanent for items already in the bin).',
            ['path' => $path, 'permanent' => ['type' => 'boolean', 'default' => false]], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $info = $this->mega->describe($node);
                $this->mega->delete($node, $a['permanent']);
                return ['deleted' => true, 'permanent' => $a['permanent'] || str_starts_with($info['path'], 'trash:')] + $info;
            }, $destructive);

        $r->add('mega_restore', 'Restore from Rubbish Bin', 'Move an item out of the Rubbish Bin, back to its original folder (or to a given destination).',
            ['path' => $path, 'destination' => $folder('Optional destination folder.')], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $target = $a['destination'] !== null ? $this->mega->resolve($a['destination']) : null;
                $this->mega->restore($node, $target);
                return ['restored' => true] + $this->mega->describe($node);
            });

        $r->add('mega_empty_trash', 'Empty Rubbish Bin', 'Permanently delete everything in the Rubbish Bin.', [], [],
            fn () => ['deleted' => $this->mega->emptyTrash()], $destructive);

        $r->add('mega_set_label', 'Set color label', 'Set or clear the color label of a file/folder.',
            ['path' => $path, 'label' => ['type' => 'string', 'enum' => ['none', 'red', 'orange', 'yellow', 'green', 'blue', 'purple', 'grey']]],
            ['path', 'label'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $this->mega->setLabel($node, $a['label'] === 'none' ? '' : $a['label']);
                return $this->mega->describe($node);
            });

        $r->add('mega_set_favorite', 'Set favorite', 'Mark or unmark a file/folder as favorite.',
            ['path' => $path, 'favorite' => ['type' => 'boolean', 'default' => true]], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $this->mega->setFavorite($node, $a['favorite']);
                return $this->mega->describe($node);
            });

        // -------------------------------------------------------------- content
        $r->add('mega_read_file', 'Read file', 'Download and decrypt a file (or a byte range) and return it as text or base64.',
            [
                'path' => $path,
                'encoding' => ['type' => 'string', 'enum' => ['utf8', 'base64'], 'default' => 'utf8'],
                'start' => ['type' => 'integer', 'default' => 0, 'minimum' => 0],
                'maxBytes' => ['type' => 'integer', 'default' => min(1048576, $this->maxReadBytes), 'minimum' => 1, 'maximum' => $this->maxReadBytes],
            ], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $data = $this->mega->read($node, $a['start'], $a['maxBytes']);
                return $this->mega->describe($node) + $this->content($data, $a['encoding'], $a['start'], (int) $node->size);
            }, $readOnly);

        $r->add('mega_write_file', 'Write file', 'Create a file from text or base64 content. With overwrite=true an existing file of the same name is replaced (the old version goes to the Rubbish Bin).',
            [
                'path' => $path,
                'content' => ['type' => 'string'],
                'encoding' => ['type' => 'string', 'enum' => ['utf8', 'base64'], 'default' => 'utf8'],
                'overwrite' => ['type' => 'boolean', 'default' => false],
            ], ['path', 'content'],
            function ($a) {
                [$parentRef, $name] = MegaClient::splitParent($a['path']);
                $data = $a['encoding'] === 'base64' ? base64_decode($a['content'], true) : $a['content'];
                if ($data === false) {
                    throw new MegaException('content is not valid base64');
                }
                if (strlen($data) > $this->maxUploadBytes) {
                    throw new MegaException('content exceeds max_upload_bytes');
                }
                $parent = $this->mega->ensureFolder($parentRef);
                $existing = $parent->child($name);
                if ($existing !== null && ($existing->isFolder() || !$a['overwrite'])) {
                    throw new MegaException("\"{$a['path']}\" already exists" . ($existing->isFolder() ? ' as a folder' : ' (set overwrite=true)'));
                }
                $node = $this->mega->uploadString($parent, $name, $data);
                if ($existing !== null) {
                    $this->mega->delete($existing, false);
                }
                return ['written' => true] + $this->mega->describe($node);
            });

        $r->add('mega_upload_from_url', 'Upload from URL', 'The server downloads a public http(s) URL and uploads it to MEGA, encrypted.',
            [
                'url' => ['type' => 'string'],
                'remoteFolder' => $folder('Destination folder (created if missing).', '/'),
                'name' => ['type' => 'string', 'description' => 'File name on MEGA (default: from the URL)'],
            ], ['url'],
            function ($a) {
                $folderNode = $this->mega->ensureFolder($a['remoteFolder']);
                [$stream, $size, $suggested] = UrlFetcher::fetch($a['url'], $this->maxUploadBytes);
                try {
                    $node = $this->mega->upload($folderNode, $a['name'] ?: $suggested, $stream, $size);
                } finally {
                    fclose($stream);
                }
                return ['uploaded' => true] + $this->mega->describe($node);
            });

        // -------------------------------------------------------------- sharing
        $r->add('mega_create_link', 'Create public link', 'Export a file or folder with a public mega.nz link.',
            [
                'path' => $path,
                'includeKey' => ['type' => 'boolean', 'default' => true, 'description' => 'Put the decryption key in the URL; if false it is returned separately'],
            ], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $link = $this->mega->createLink($node, $a['includeKey']);
                return $link + $this->mega->describe($node);
            });

        $r->add('mega_remove_link', 'Remove public link', 'Disable the public link of a file or folder.', ['path' => $path], ['path'],
            function ($a) {
                $node = $this->mega->resolve($a['path']);
                $this->mega->removeLink($node);
                return ['linkRemoved' => true] + $this->mega->describe($node);
            });

        // -------------------------------------------------------------- public links
        $url = ['type' => 'string', 'description' => 'https://mega.nz/file/<id>#<key> or https://mega.nz/folder/<id>#<key>'];
        $r->add('mega_public_info', 'Inspect public link', 'Metadata of a public MEGA link; lists the contents for folder links. No login needed.',
            [
                'url' => $url,
                'subPath' => ['type' => 'string', 'description' => 'Path inside a shared folder'],
                'recursive' => ['type' => 'boolean', 'default' => false],
                'limit' => ['type' => 'integer', 'default' => 500, 'minimum' => 1, 'maximum' => 10000],
            ], ['url'],
            function ($a) {
                $target = $this->mega->openPublic($a['url'], $a['subPath'])['target'];
                $out = $this->mega->describe($target, false);
                if ($target->isFolder()) {
                    $entries = [];
                    $this->listTree($target, 0, $a['recursive'] ? 50 : 0, $entries, $a['limit'], false);
                    $out['entries'] = $entries;
                }
                return $out;
            }, $readOnly);

        $r->add('mega_public_read', 'Read public file', 'Return the content of a file behind a public link as text or base64. No login needed.',
            [
                'url' => $url,
                'subPath' => ['type' => 'string', 'description' => 'File path inside a folder link'],
                'encoding' => ['type' => 'string', 'enum' => ['utf8', 'base64'], 'default' => 'utf8'],
                'start' => ['type' => 'integer', 'default' => 0, 'minimum' => 0],
                'maxBytes' => ['type' => 'integer', 'default' => min(1048576, $this->maxReadBytes), 'minimum' => 1, 'maximum' => $this->maxReadBytes],
            ], ['url'],
            function ($a) {
                $opened = $this->mega->openPublic($a['url'], $a['subPath']);
                $node = $opened['target'];
                $data = $this->mega->readPublic($opened, $node, $a['start'], $a['maxBytes']);
                return $this->mega->describe($node, false) + $this->content($data, $a['encoding'], $a['start'], (int) $node->size);
            }, $readOnly);

        $r->add('mega_import_link', 'Import public link', 'Save a public file or folder link into your account (server-side, no download).',
            ['url' => $url, 'remoteFolder' => $folder('Destination folder (created if missing).', '/')], ['url'],
            fn ($a) => ['imported' => true] + $this->mega->describe(
                $this->mega->importLink($a['url'], $this->mega->ensureFolder($a['remoteFolder']))
            ));

        // -------------------------------------------------------------- advanced
        $r->add('mega_api_request', 'Raw MEGA API request',
            'Advanced: send one raw command to the MEGA API with the current session, e.g. {"a":"uq","strg":1}. '
            . 'Only for operations not covered by other tools; encrypted fields are returned as-is.',
            ['request' => ['type' => 'object', 'description' => 'API command object containing "a" (the action)']], ['request'],
            function ($a) {
                if (!is_string($a['request']['a'] ?? null)) {
                    throw new MegaException('request must contain an "a" string field');
                }
                return $this->mega->rawRequest($a['request']);
            }, $destructive);
    }

    private function listTree(Node $node, int $depth, int $maxDepth, array &$out, int $limit, bool $withPath): void
    {
        foreach ($node->children as $child) {
            if (count($out) >= $limit) {
                return;
            }
            $out[] = $this->mega->describe($child, $withPath) + ['depth' => $depth];
            if ($child->isFolder() && $depth < $maxDepth) {
                $this->listTree($child, $depth + 1, $maxDepth, $out, $limit, $withPath);
            }
        }
    }

    private function content(string $data, string $encoding, int $start, int $size): array
    {
        $end = $start + strlen($data);
        $text = $encoding === 'base64' ? base64_encode($data) : $data;
        if ($encoding === 'utf8' && !mb_check_encoding($text, 'UTF-8')) {
            $text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
        }
        return ['range' => [$start, max($start, $end - 1)], 'truncated' => $end < $size, 'encoding' => $encoding, 'content' => $text];
    }

    private static function bytes(int $n): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        $v = (float) $n;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return $i === 0 ? "{$n} B" : sprintf('%.2f %s', $v, $units[$i]);
    }
}
