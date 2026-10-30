<?php
declare(strict_types=1);

namespace Dmar\Controllers;

use Dmar\Database\Connection;
use Dmar\Http\ImageUploadMiddleware;
use Dmar\Http\Response;
use RuntimeException;
use Throwable;

final class ProfileController
{
    public function uploadMechanicImage(): void
    {
        $user = $_SESSION['dmar_user'] ?? null;
        if (!is_array($user) || !in_array(($user['portal'] ?? ''), ['mekanik', 'staff'], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Silakan masuk untuk mengganti foto profil.']], 403);
            return;
        }
        $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $known = $_SESSION['dmar_csrf'] ?? '';
        if (!is_string($sent) || !is_string($known) || $known === '' || !hash_equals($known, $sent)) {
            Response::json(['ok' => false, 'error' => ['code' => 'csrf_failed', 'message' => 'Token keamanan tidak valid. Muat ulang halaman lalu coba lagi.']], 403);
            return;
        }
        if (!isset($_FILES['profileImage']) || !is_array($_FILES['profileImage'])) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Pilih foto profil terlebih dahulu.']], 422);
            return;
        }

        $imagePath = null;
        try {
            $imagePath = (new ImageUploadMiddleware())->storeWebp($_FILES['profileImage'], 'profiles');
            $db = Connection::create();
            $isMechanic = $user['portal'] === 'mekanik';
            $table = $isMechanic ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
            $idColumn = $isMechanic ? '_id_mtc_crew' : '_id_mtc_fm';
            $lookup = $db->prepare("SELECT profile_image_path FROM {$table} WHERE {$idColumn} = :id LIMIT 1");
            $lookup->execute(['id' => (int) $user['id']]);
            $oldPath = $lookup->fetchColumn();
            if ($oldPath === false) {
                ImageUploadMiddleware::delete($imagePath);
                Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Akun tidak ditemukan. Silakan masuk kembali.']], 404);
                return;
            }
            $update = $db->prepare("UPDATE {$table} SET profile_image_path = :image WHERE {$idColumn} = :id");
            $update->execute(['image' => $imagePath, 'id' => (int) $user['id']]);
            ImageUploadMiddleware::delete(is_string($oldPath) ? $oldPath : null);
            Response::json(['ok' => true, 'data' => ['profileImageUrl' => ImageUploadMiddleware::url($imagePath)]]);
        } catch (RuntimeException $error) {
            ImageUploadMiddleware::delete($imagePath);
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $error->getMessage()]], 422);
        } catch (Throwable $error) {
            ImageUploadMiddleware::delete($imagePath);
            error_log('DMAR mechanic profile image upload failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Foto profil gagal disimpan. Coba lagi beberapa saat.']], 503);
        }
    }
}
