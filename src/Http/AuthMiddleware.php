<?php
declare(strict_types=1);

namespace Dmar\Http;

use Dmar\Database\Connection;
use Dmar\Security\RememberMe;
use Throwable;

final class AuthMiddleware
{
    private const PUBLIC_ROUTES = [
        'GET /api/v1/health',
        'POST /api/v1/auth/login',
    ];

    public static function isPublicRequest(string $method, string $path): bool
    {
        return in_array($method . ' ' . $path, self::PUBLIC_ROUTES, true)
            || ($method === 'GET' && preg_match('#^/api/v1/media/(profiles|units)/[a-f0-9]{32}\.webp$#', $path) === 1);
    }

    public static function requireValidSession(): bool
    {
        $portal = strtolower(trim((string) ($_SERVER['HTTP_X_DMAR_PORTAL'] ?? '')));
        $user = $_SESSION['dmar_user'] ?? null;
        $validPortal = in_array($portal, ['mekanik', 'staff'], true);
        $validIdentity = is_array($user)
            && isset($user['id'])
            && filter_var($user['id'], FILTER_VALIDATE_INT) !== false
            && (int) $user['id'] > 0
            && ($user['portal'] ?? null) === $portal;
        $validRole = is_array($user) && (
            ($portal === 'mekanik' && ($user['role'] ?? null) === 'mechanic')
            || ($portal === 'staff' && in_array($user['role'] ?? null, ['foreman', 'admin', 'superadmin'], true))
        );

        if ($validPortal && $validIdentity && $validRole) {
            try {
                $isMechanic = $portal === 'mekanik';
                $table = $isMechanic ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
                $idColumn = $isMechanic ? '_id_mtc_crew' : '_id_mtc_fm';
                $db = Connection::create();
                $query = $db->prepare("SELECT status_data FROM {$table} WHERE {$idColumn} = :id LIMIT 1");
                $query->execute(['id' => (int) $user['id']]);
                if ((int) $query->fetchColumn() === 1) return true;

                RememberMe::revokeUser($db, $portal, (int) $user['id']);
                $_SESSION = [];
                session_destroy();
                Response::json([
                    'ok' => false,
                    'error' => ['code' => 'account_inactive', 'message' => 'Akun ini sudah dinonaktifkan. Hubungi admin jika memerlukan bantuan.'],
                ], 401);
                return false;
            } catch (Throwable $error) {
                error_log('DMAR active account check failed: ' . $error->getMessage());
                Response::json([
                    'ok' => false,
                    'error' => ['code' => 'service_unavailable', 'message' => 'Status akun sementara tidak dapat diperiksa.'],
                ], 503);
                return false;
            }
        }

        Response::json([
            'ok' => false,
            'error' => [
                'code' => 'unauthenticated',
                'message' => 'Sesi tidak valid atau telah berakhir. Silakan masuk kembali.',
            ],
        ], 401);
        return false;
    }
}
