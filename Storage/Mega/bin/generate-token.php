<?php

// Prints a random token suitable for auth_tokens / session_secret.
echo bin2hex(random_bytes(32)), PHP_EOL;
