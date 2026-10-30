<?php
declare(strict_types=1);

namespace Dmar\Controllers;

use Dmar\Database\Connection;
use Dmar\Http\Request;
use Dmar\Http\Response;
use Dmar\Http\ImageUploadMiddleware;
use Dmar\Security\RememberMe;
use JsonException;
use Throwable;

final class AuthController
{
    public function login(): void
    {
        try {
            $input = Request::json();
        } catch (JsonException) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Body JSON tidak valid']], 400);
            return;
        }

        $portal = $input['portal'] ?? null;
        $portalContext = $_SERVER['HTTP_X_DMAR_PORTAL'] ?? '';
        $nrpp = isset($input['nrpp']) && is_string($input['nrpp']) ? trim($input['nrpp']) : '';
        $password = isset($input['password']) && is_string($input['password']) ? $input['password'] : '';
        $rememberMe = ($input['rememberMe'] ?? false) === true;

        if (!in_array($portalContext, ['mekanik', 'staff'], true) || $portal !== $portalContext) {
            Response::json(['ok' => false, 'error' => ['code' => 'portal_mismatch', 'message' => 'Konteks portal tidak sesuai']], 400);
            return;
        }
        if (!in_array($portal, ['mekanik', 'staff'], true) || $nrpp === '' || $password === '') {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Portal, NRPP, dan password wajib diisi']], 422);
            return;
        }

        $isMekanik = $portal === 'mekanik';
        $table = $isMekanik ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
        $idColumn = $isMekanik ? '_id_mtc_crew' : '_id_mtc_fm';
        $siteJoin = 'LEFT JOIN tb_job_sites js ON js.id = u.job_site_id';
        $assignmentSelect = $isMekanik ? 'NULL AS assignedJobSiteNames' : "(SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames";

        try {
            $query = Connection::create()->prepare(
                "SELECT u.{$idColumn} AS id, u.nrpp, u.nama, u.jabatan, u.password, u.level_access, u.job_site_id AS jobSiteId, u.profile_image_path AS profileImagePath, js.name AS jobSiteName, {$assignmentSelect} FROM {$table} u {$siteJoin} WHERE u.nrpp = :nrpp AND u.status_data = 1 LIMIT 1"
            );
            $query->execute(['nrpp' => $nrpp]);
            $account = $query->fetch();
        } catch (Throwable $error) {
            error_log('DMAR login query failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Layanan autentikasi sementara tidak tersedia']], 503);
            return;
        }

        if (!$account || !is_string($account['password']) || !password_verify($password, $account['password'])) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_credentials', 'message' => 'NRPP atau password salah']], 401);
            return;
        }

        $staffLevel = (int) $account['level_access'];
        if (!$isMekanik && !in_array($staffLevel, [0, 1, 2], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_role', 'message' => 'Level akses akun tidak valid']], 403);
            return;
        }
        $role = $isMekanik ? 'mechanic' : match ($staffLevel) {
            0 => 'foreman',
            1 => 'admin',
            2 => 'superadmin',
        };
        RememberMe::revokeCurrent($portal);
        if ($rememberMe) {
            try {
                RememberMe::issue($portal, (int) $account['id']);
            } catch (Throwable $error) {
                error_log('DMAR remember-me issue failed: ' . $error->getMessage());
                Response::json(['ok' => false, 'error' => ['code' => 'remember_me_unavailable', 'message' => 'Fitur Ingat saya belum siap. Pastikan migrasi database sudah diterapkan.']], 503);
                return;
            }
        }
        session_regenerate_id(true);
        $_SESSION['dmar_user'] = [
            'id' => (int) $account['id'],
            'nrpp' => (string) $account['nrpp'],
            'name' => (string) $account['nama'],
            'position' => (string) ($account['jabatan'] ?? ''),
            'portal' => $portal,
            'role' => $role,
            'jobSiteId' => isset($account['jobSiteId']) ? (int) $account['jobSiteId'] : null,
            'jobSiteName' => !$isMekanik && (int) $account['level_access'] === 0 ? (string) ($account['assignedJobSiteNames'] ?? '') ?: null : (isset($account['jobSiteName']) ? (string) $account['jobSiteName'] : null),
            'profileImageUrl' => ImageUploadMiddleware::url(isset($account['profileImagePath']) ? (string) $account['profileImagePath'] : null),
        ];
        $_SESSION['dmar_csrf'] = bin2hex(random_bytes(32));

        Response::json(['ok' => true, 'data' => [
            'user' => $_SESSION['dmar_user'],
            'csrfToken' => $_SESSION['dmar_csrf'],
        ]]);
    }

    public function me(): void
    {
        $portalContext = $_SERVER['HTTP_X_DMAR_PORTAL'] ?? '';
        if (!isset($_SESSION['dmar_user']) || !is_array($_SESSION['dmar_user']) || ($_SESSION['dmar_user']['portal'] ?? null) !== $portalContext) {
            Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk terlebih dahulu']], 401);
            return;
        }

        if (!in_array($portalContext, ['mekanik', 'staff'], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk terlebih dahulu']], 401);
            return;
        }

        try {
            $isMekanik = $portalContext === 'mekanik';
            $table = $isMekanik ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
            $idColumn = $isMekanik ? '_id_mtc_crew' : '_id_mtc_fm';
            $assignmentSelect = $isMekanik ? 'NULL AS assignedJobSiteNames' : "(SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames";
            $query = Connection::create()->prepare(
                "SELECT u.{$idColumn} AS id, u.nrpp, u.nama, u.jabatan, u.level_access, u.job_site_id AS jobSiteId, u.profile_image_path AS profileImagePath, js.name AS jobSiteName, {$assignmentSelect} FROM {$table} u LEFT JOIN tb_job_sites js ON js.id = u.job_site_id WHERE u.{$idColumn} = :id AND u.status_data = 1 LIMIT 1"
            );
            $query->execute(['id' => (int) $_SESSION['dmar_user']['id']]);
            $account = $query->fetch();
            if (!$account) {
                $_SESSION = [];
                session_destroy();
                Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Akun tidak ditemukan. Silakan masuk kembali']], 401);
                return;
            }
            $level = (int) $account['level_access'];
            if (!$isMekanik && !in_array($level, [0, 1, 2], true)) {
                Response::json(['ok' => false, 'error' => ['code' => 'invalid_role', 'message' => 'Level akses akun tidak valid']], 403);
                return;
            }
            $_SESSION['dmar_user'] = [
                'id' => (int) $account['id'],
                'nrpp' => (string) $account['nrpp'],
                'name' => (string) $account['nama'],
                'position' => (string) ($account['jabatan'] ?? ''),
                'portal' => $portalContext,
                'role' => $isMekanik ? 'mechanic' : match ($level) { 0 => 'foreman', 1 => 'admin', 2 => 'superadmin' },
                'jobSiteId' => isset($account['jobSiteId']) ? (int) $account['jobSiteId'] : null,
                'jobSiteName' => !$isMekanik && (int) $account['level_access'] === 0 ? (string) ($account['assignedJobSiteNames'] ?? '') ?: null : (isset($account['jobSiteName']) ? (string) $account['jobSiteName'] : null),
                'profileImageUrl' => ImageUploadMiddleware::url(isset($account['profileImagePath']) ? (string) $account['profileImagePath'] : null),
            ];
        } catch (Throwable $error) {
            error_log('DMAR session refresh failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Status sesi sementara tidak tersedia']], 503);
            return;
        }

        Response::json(['ok' => true, 'data' => [
            'user' => $_SESSION['dmar_user'],
            'csrfToken' => $_SESSION['dmar_csrf'] ?? null,
        ]]);
    }

    public function logout(): void
    {
        $sentToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $sessionToken = $_SESSION['dmar_csrf'] ?? '';
        if (!is_string($sentToken) || !is_string($sessionToken) || $sessionToken === '' || !hash_equals($sessionToken, $sentToken)) {
            Response::json(['ok' => false, 'error' => ['code' => 'csrf_failed', 'message' => 'Token keamanan tidak valid']], 403);
            return;
        }

        RememberMe::revokeCurrent((string) ($_SESSION['dmar_user']['portal'] ?? ''));

        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Lax',
            ]);
        }
        session_destroy();

        Response::json(['ok' => true, 'data' => ['loggedOut' => true]]);
    }

    public function changeMechanicPassword(): void
    {
        $sentToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $sessionToken = $_SESSION['dmar_csrf'] ?? '';
        $user = $_SESSION['dmar_user'] ?? null;
        if (!is_string($sentToken) || !is_string($sessionToken) || $sessionToken === '' || !hash_equals($sessionToken, $sentToken)) {
            Response::json(['ok' => false, 'error' => ['code' => 'csrf_failed', 'message' => 'Token keamanan tidak valid']], 403);
            return;
        }
        if (!is_array($user) || !in_array(($user['portal'] ?? ''), ['mekanik', 'staff'], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk terlebih dahulu']], 401);
            return;
        }

        try {
            $input = Request::json();
        } catch (JsonException) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Body JSON tidak valid']], 400);
            return;
        }
        $currentPassword = isset($input['currentPassword']) && is_string($input['currentPassword']) ? $input['currentPassword'] : '';
        $newPassword = isset($input['newPassword']) && is_string($input['newPassword']) ? $input['newPassword'] : '';
        if ($currentPassword === '' || strlen($newPassword) < 8) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Password lama wajib diisi dan password baru minimal 8 karakter']], 422);
            return;
        }
        if (hash_equals($currentPassword, $newPassword)) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Password baru harus berbeda dari password saat ini']], 422);
            return;
        }

        try {
            $db = Connection::create();
            $isMechanic = $user['portal'] === 'mekanik';
            $table = $isMechanic ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
            $idColumn = $isMechanic ? '_id_mtc_crew' : '_id_mtc_fm';
            $query = $db->prepare("SELECT password FROM {$table} WHERE {$idColumn} = :id LIMIT 1");
            $query->execute(['id' => (int) $user['id']]);
            $currentHash = $query->fetchColumn();
            if (!is_string($currentHash) || !password_verify($currentPassword, $currentHash)) {
                Response::json(['ok' => false, 'error' => ['code' => 'invalid_current_password', 'message' => 'Password lama tidak sesuai']], 422);
                return;
            }

            $update = $db->prepare("UPDATE {$table} SET password = :password WHERE {$idColumn} = :id");
            $update->execute(['password' => password_hash($newPassword, PASSWORD_DEFAULT), 'id' => (int) $user['id']]);
            RememberMe::revokeUser($db, (string) $user['portal'], (int) $user['id']);
            session_regenerate_id(true);
            $_SESSION['dmar_csrf'] = bin2hex(random_bytes(32));
            Response::json(['ok' => true, 'data' => ['changed' => true, 'csrfToken' => $_SESSION['dmar_csrf']]]);
        } catch (Throwable $error) {
            error_log('DMAR account password change failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Password gagal diubah. Coba lagi']], 503);
        }
    }
}
