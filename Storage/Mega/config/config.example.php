<?php

// Copy to config/config.php and fill in. Environment variables, when set, override these values.
return [
    // Bearer tokens accepted by the MCP endpoint (at least 32 characters each).
    // Generate one with: php bin/generate-token.php
    // Env: MCP_AUTH_TOKENS (comma separated)
    'auth_tokens' => [
        // 'paste-a-generated-token-here',
    ],

    // Also accept the token as ?token=... in the URL, for clients that cannot send headers.
    // Less secure (URLs end up in logs): keep false if possible.
    'allow_query_token' => false,

    // If non-empty, requests carrying an Origin header must match one of these.
    'allowed_origins' => [],

    'mega' => [
        // Env: MEGA_EMAIL / MEGA_PASSWORD
        'email' => '',
        'password' => '',
        // Where the encrypted MEGA session is cached. Must be writable and NOT web-accessible.
        'storage_dir' => __DIR__ . '/../var',
        // Secret used to encrypt the cached session (at least 32 characters). Env: MEGA_SESSION_SECRET
        'session_secret' => '',
    ],

    'limits' => [
        // Max bytes returned by mega_read_file / mega_public_read in one call.
        'max_read_bytes' => 10 * 1024 * 1024,
        // Max size for mega_write_file and mega_upload_from_url.
        'max_upload_bytes' => 200 * 1024 * 1024,
    ],
];
