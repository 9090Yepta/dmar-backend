<?php
declare(strict_types=1);

$backendRoot = dirname(__DIR__);
$envFile = $backendRoot . DIRECTORY_SEPARATOR . '.env';

if (is_file($envFile) && is_readable($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$name, $value] = array_map('trim', explode('=', $line, 2));
        if ($name === '' || getenv($name) !== false) {
            continue;
        }

        if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
            $value = substr($value, 1, -1);
        }

        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
    }
}

$portalContext = strtolower(trim((string) ($_SERVER['HTTP_X_DMAR_PORTAL'] ?? '')));
$requestOrigin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
$allowedOrigins = array_values(array_filter(array_map(
    'trim',
    explode(',', (string) (getenv('CORS_ALLOWED_ORIGINS') ?: ''))
)));
if (!$allowedOrigins && (getenv('APP_ENV') ?: 'local') === 'local') {
    $allowedOrigins = [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:5174',
        'http://127.0.0.1:5174',
    ];
}

header('Vary: Origin');
if ($requestOrigin !== '') {
    if (!in_array($requestOrigin, $allowedOrigins, true)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(['ok' => false, 'error' => ['code' => 'origin_not_allowed', 'message' => 'Origin tidak diizinkan']], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }
    header('Access-Control-Allow-Origin: ' . $requestOrigin);
    header('Access-Control-Allow-Credentials: true');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-DMAR-Portal, X-CSRF-Token');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    $https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off';
    $secureSetting = getenv('COOKIE_SECURE');
    $secureCookie = $secureSetting === false ? $https : filter_var($secureSetting, FILTER_VALIDATE_BOOLEAN);
    $sessionName = match ($portalContext) {
        'mekanik' => 'DMARMEKANIKSESSID',
        'staff' => 'DMARSTAFFSESSID',
        default => 'DMARSESSID',
    };
    session_name($sessionName);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $secureCookie,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'Dmar\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));
    $file = __DIR__ . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $relativeClass) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

\Dmar\Security\RememberMe::restore($portalContext);
