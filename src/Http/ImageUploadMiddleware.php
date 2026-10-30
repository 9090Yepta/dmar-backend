<?php
declare(strict_types=1);

namespace Dmar\Http;

use RuntimeException;

final class ImageUploadMiddleware
{
    private const MAX_BYTES = 5242880;
    private const MAX_PIXELS = 25000000;
    private const WEBP_QUALITY = 92;

    /** Convert a user-provided image to WebP and return its relative storage path. */
    public function storeWebp(array $upload, string $bucket): string
    {
        if (!in_array($bucket, ['profiles', 'units'], true)) {
            throw new RuntimeException('Tujuan penyimpanan gambar tidak valid.');
        }
        if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            $message = match ((int) ($upload['error'] ?? UPLOAD_ERR_NO_FILE)) {
                UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Ukuran gambar melebihi batas server.',
                UPLOAD_ERR_PARTIAL => 'Upload gambar terputus. Silakan pilih ulang.',
                UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE => 'Server tidak dapat menyimpan gambar saat ini.',
                default => 'Pilih foto terlebih dahulu.',
            };
            throw new RuntimeException($message);
        }

        $tmp = $upload['tmp_name'] ?? '';
        $size = (int) ($upload['size'] ?? 0);
        if (!is_string($tmp) || !is_uploaded_file($tmp) || $size < 1 || $size > self::MAX_BYTES) {
            throw new RuntimeException('Foto harus berukuran maksimal 5 MB.');
        }

        $bytes = file_get_contents($tmp);
        if ($bytes === false) throw new RuntimeException('File gambar tidak dapat dibaca.');
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->buffer($bytes);
        if (!in_array($mime, ['image/jpeg', 'image/png', 'image/webp'], true)) {
            throw new RuntimeException('Format foto harus JPG, PNG, atau WebP.');
        }
        $dimensions = @getimagesizefromstring($bytes);
        if (!$dimensions || $dimensions[0] < 1 || $dimensions[1] < 1 || $dimensions[0] * $dimensions[1] > self::MAX_PIXELS) {
            throw new RuntimeException('File bukan gambar yang valid atau resolusinya terlalu besar.');
        }
        $image = @imagecreatefromstring($bytes);
        if ($image === false) throw new RuntimeException('Foto tidak dapat diproses. Coba simpan ulang sebagai JPG, PNG, atau WebP.');

        $root = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . $bucket;
        if (!is_dir($root) && !mkdir($root, 0750, true) && !is_dir($root)) {
            imagedestroy($image);
            throw new RuntimeException('Folder penyimpanan foto belum dapat dibuat.');
        }
        $filename = bin2hex(random_bytes(16)) . '.webp';
        $target = $root . DIRECTORY_SEPARATOR . $filename;
        // Keep more detail in profile and unit photos while still converting to WebP.
        $saved = imagewebp($image, $target, self::WEBP_QUALITY);
        imagedestroy($image);
        if (!$saved) throw new RuntimeException('Foto gagal dikonversi ke WebP.');

        return $bucket . '/' . $filename;
    }

    public static function url(?string $storedPath): ?string
    {
        if (!$storedPath || preg_match('#^(profiles|units)/[a-f0-9]{32}\.webp$#', $storedPath) !== 1) return null;
        return '/api/v1/media/' . $storedPath;
    }

    public static function delete(?string $storedPath): void
    {
        if (!$storedPath || preg_match('#^(profiles|units)/[a-f0-9]{32}\.webp$#', $storedPath) !== 1) return;
        $path = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $storedPath);
        if (is_file($path)) @unlink($path);
    }

    public static function serve(string $bucket, string $filename): void
    {
        if (!in_array($bucket, ['profiles', 'units'], true) || preg_match('/^[a-f0-9]{32}\.webp$/', $filename) !== 1) {
            Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Gambar tidak ditemukan']], 404);
            return;
        }
        $path = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . $bucket . DIRECTORY_SEPARATOR . $filename;
        if (!is_file($path)) {
            Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Gambar tidak ditemukan']], 404);
            return;
        }
        header('Content-Type: image/webp');
        header('Cache-Control: public, max-age=86400, immutable');
        header('X-Content-Type-Options: nosniff');
        header('Content-Length: ' . (string) filesize($path));
        readfile($path);
    }
}
