<?php
declare(strict_types=1);

namespace Dmar\Security;

use Dmar\Database\Connection;
use PDO;
use Throwable;

final class RememberMe
{
    private const COOKIE_PATH = '/api/v1';
    private const LIFETIME_SECONDS = 60 * 60 * 24 * 30;

    public static function restore(string $portal): void
    {
        if (!in_array($portal, ['mekanik', 'staff'], true) || isset($_SESSION['dmar_user'])) {
            return;
        }

        $cookieName = self::cookieName($portal);
        $parts = self::parseToken($_COOKIE[$cookieName] ?? null);
        if ($parts === null) {
            return;
        }

        [$selector, $validator] = $parts;
        try {
            $pdo = Connection::create();
            $tokenQuery = $pdo->prepare(
                'SELECT token_hash, user_id FROM dmar_remember_tokens WHERE selector = :selector AND portal = :portal AND expires_at > UTC_TIMESTAMP() LIMIT 1'
            );
            $tokenQuery->execute(['selector' => $selector, 'portal' => $portal]);
            $token = $tokenQuery->fetch();

            if (!$token || !hash_equals((string) $token['token_hash'], hash('sha256', $validator))) {
                self::clearCookie($portal);
                return;
            }

            $isMekanik = $portal === 'mekanik';
            $table = $isMekanik ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
            $idColumn = $isMekanik ? '_id_mtc_crew' : '_id_mtc_fm';
            $assignmentSelect = $isMekanik ? 'NULL AS assignedJobSiteNames' : "(SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames";
            $accountQuery = $pdo->prepare(
                "SELECT u.{$idColumn} AS id, u.nrpp, u.nama, u.jabatan, u.level_access, u.job_site_id AS jobSiteId, js.name AS jobSiteName, {$assignmentSelect} FROM {$table} u LEFT JOIN tb_job_sites js ON js.id = u.job_site_id WHERE u.{$idColumn} = :id AND u.status_data = 1 LIMIT 1"
            );
            $accountQuery->execute(['id' => (int) $token['user_id']]);
            $account = $accountQuery->fetch();

            if (!$account) {
                $pdo->prepare('DELETE FROM dmar_remember_tokens WHERE selector = :selector')->execute(['selector' => $selector]);
                self::clearCookie($portal);
                return;
            }

            if (!$isMekanik && !in_array((int) $account['level_access'], [0, 1, 2], true)) {
                $pdo->prepare('DELETE FROM dmar_remember_tokens WHERE selector = :selector')->execute(['selector' => $selector]);
                self::clearCookie($portal);
                return;
            }

            session_regenerate_id(true);
            $_SESSION['dmar_user'] = self::userData($account, $portal);
            $_SESSION['dmar_csrf'] = bin2hex(random_bytes(32));
            $pdo->prepare('UPDATE dmar_remember_tokens SET last_used_at = UTC_TIMESTAMP() WHERE selector = :selector')
                ->execute(['selector' => $selector]);
        } catch (Throwable $error) {
            error_log('DMAR remember-me restore failed: ' . $error->getMessage());
        }
    }

    public static function issue(string $portal, int $userId): void
    {
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $expiresAt = gmdate('Y-m-d H:i:s', time() + self::LIFETIME_SECONDS);

        $pdo = Connection::create();
        $pdo->exec('DELETE FROM dmar_remember_tokens WHERE expires_at <= UTC_TIMESTAMP()');
        $query = $pdo->prepare(
            'INSERT INTO dmar_remember_tokens (selector, token_hash, portal, user_id, expires_at) VALUES (:selector, :token_hash, :portal, :user_id, :expires_at)'
        );
        $query->execute([
            'selector' => $selector,
            'token_hash' => hash('sha256', $validator),
            'portal' => $portal,
            'user_id' => $userId,
            'expires_at' => $expiresAt,
        ]);

        setcookie(self::cookieName($portal), $selector . '.' . $validator, self::cookieOptions($portal, time() + self::LIFETIME_SECONDS));
    }

    public static function revokeCurrent(string $portal): void
    {
        if (!in_array($portal, ['mekanik', 'staff'], true)) {
            return;
        }

        $parts = self::parseToken($_COOKIE[self::cookieName($portal)] ?? null);
        self::clearCookie($portal);
        if ($parts === null) {
            return;
        }

        try {
            Connection::create()->prepare('DELETE FROM dmar_remember_tokens WHERE selector = :selector AND portal = :portal')
                ->execute(['selector' => $parts[0], 'portal' => $portal]);
        } catch (Throwable $error) {
            error_log('DMAR remember-me revoke failed: ' . $error->getMessage());
        }
    }

    public static function revokeUser(PDO $pdo, string $portal, int $userId): void
    {
        try {
            $pdo->prepare('DELETE FROM dmar_remember_tokens WHERE portal = :portal AND user_id = :user_id')
                ->execute(['portal' => $portal, 'user_id' => $userId]);
        } catch (Throwable $error) {
            error_log('DMAR remember-me account revoke failed: ' . $error->getMessage());
        }
    }

    private static function userData(array $account, string $portal): array
    {
        $isMekanik = $portal === 'mekanik';
        return [
            'id' => (int) $account['id'],
            'nrpp' => (string) $account['nrpp'],
            'name' => (string) $account['nama'],
            'position' => (string) ($account['jabatan'] ?? ''),
            'portal' => $portal,
            'role' => $isMekanik ? 'mechanic' : match ((int) $account['level_access']) {
                0 => 'foreman',
                1 => 'admin',
                2 => 'superadmin',
            },
            'jobSiteId' => isset($account['jobSiteId']) ? (int) $account['jobSiteId'] : null,
            'jobSiteName' => (int) $account['level_access'] === 0 ? (string) ($account['assignedJobSiteNames'] ?? '') ?: null : (isset($account['jobSiteName']) ? (string) $account['jobSiteName'] : null),
        ];
    }

    private static function parseToken(mixed $cookie): ?array
    {
        if (!is_string($cookie) || !preg_match('/\A([a-f0-9]{32})\.([a-f0-9]{64})\z/i', $cookie, $matches)) {
            return null;
        }
        return [strtolower($matches[1]), strtolower($matches[2])];
    }

    private static function cookieName(string $portal): string
    {
        return $portal === 'mekanik' ? 'DMARMEKANIKREMEMBER' : 'DMARSTAFFREMEMBER';
    }

    private static function cookieOptions(string $portal, int $expires): array
    {
        $https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off';
        $secureSetting = getenv('COOKIE_SECURE');
        $secureCookie = $secureSetting === false ? $https : filter_var($secureSetting, FILTER_VALIDATE_BOOLEAN);
        return [
            'expires' => $expires,
            'path' => self::COOKIE_PATH,
            'secure' => $secureCookie,
            'httponly' => true,
            'samesite' => 'Lax',
        ];
    }

    private static function clearCookie(string $portal): void
    {
        setcookie(self::cookieName($portal), '', self::cookieOptions($portal, time() - 3600));
    }
}
