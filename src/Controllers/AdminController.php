<?php
declare(strict_types=1);

namespace Dmar\Controllers;

use Dmar\Database\Connection;
use Dmar\Database\ReportActivities;
use Dmar\Http\Request;
use Dmar\Http\Response;
use Dmar\Http\ImageUploadMiddleware;
use Dmar\Security\RememberMe;
use JsonException;
use PDO;
use Throwable;
use RuntimeException;

final class AdminController
{
    private function db(bool $superadminOnly = false): ?PDO
    {
        $user = $_SESSION['dmar_user'] ?? null;
        if (!is_array($user) || ($user['portal'] ?? '') !== 'staff') {
            Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk sebagai staff']], 401);
            return null;
        }
        try {
            $db = Connection::create();
            $query = $db->prepare(
                "SELECT u._id_mtc_fm AS id, u.nrpp, u.nama, u.jabatan, u.level_access, u.job_site_id AS jobSiteId, js.name AS jobSiteName, (SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames FROM tb_users_mtc_fm u LEFT JOIN tb_job_sites js ON js.id = u.job_site_id WHERE u._id_mtc_fm = :id AND u.status_data = 1 LIMIT 1"
            );
            $query->execute(['id' => (int) ($user['id'] ?? 0)]);
            $account = $query->fetch();
            if (!$account || !in_array((int) $account['level_access'], [0, 1, 2], true)) {
                $_SESSION = [];
                session_destroy();
                Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Akun tidak ditemukan atau level akses tidak valid. Silakan masuk kembali']], 401);
                return null;
            }
            $level = (int) $account['level_access'];
            $_SESSION['dmar_user'] = [
                'id' => (int) $account['id'],
                'nrpp' => (string) $account['nrpp'],
                'name' => (string) $account['nama'],
                'position' => (string) ($account['jabatan'] ?? ''),
                'portal' => 'staff',
                'role' => match ($level) { 0 => 'foreman', 1 => 'admin', 2 => 'superadmin' },
                'jobSiteId' => isset($account['jobSiteId']) ? (int) $account['jobSiteId'] : null,
                'jobSiteName' => $level === 0 ? (string) ($account['assignedJobSiteNames'] ?? '') ?: null : (isset($account['jobSiteName']) ? (string) $account['jobSiteName'] : null),
            ];
            $user = $_SESSION['dmar_user'];
        } catch (Throwable $error) {
            error_log('DMAR admin account refresh failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Status akun admin sementara tidak tersedia']], 503);
            return null;
        }
        if (!in_array(($user['role'] ?? ''), ['admin', 'superadmin'], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Fitur ini hanya tersedia untuk admin']], 403);
            return null;
        }
        if ($superadminOnly && $user['role'] !== 'superadmin') {
            Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Fitur ini hanya tersedia untuk superadmin']], 403);
            return null;
        }
        if ($user['role'] === 'admin' && (int) ($user['jobSiteId'] ?? 0) < 1) {
            Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Akun admin belum ditempatkan pada job site']], 403);
            return null;
        }
        return $db;
    }

    private function csrf(): bool
    {
        $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $known = $_SESSION['dmar_csrf'] ?? '';
        if (is_string($sent) && is_string($known) && $known !== '' && hash_equals($known, $sent)) return true;
        Response::json(['ok' => false, 'error' => ['code' => 'csrf_failed', 'message' => 'Token keamanan tidak valid']], 403);
        return false;
    }

    /** @return array<string, mixed>|null */
    private function input(): ?array
    {
        $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
        if (str_starts_with($contentType, 'multipart/form-data')) {
            $input = $_POST;
            if (isset($input['jobSiteIds']) && is_string($input['jobSiteIds'])) {
                $decoded = json_decode($input['jobSiteIds'], true);
                if (is_array($decoded)) $input['jobSiteIds'] = $decoded;
            }
            return $input;
        }
        try { return Request::json(); } catch (JsonException) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Body JSON tidak valid']], 400);
            return null;
        }
    }

    /** @return array{table:string,id:string,reference:string,scope:string,level:int|null} */
    private function userTable(string $role): array
    {
        return match ($role) {
            'mechanic' => ['table' => 'tb_users_mtc_crew', 'id' => '_id_mtc_crew', 'reference' => '_id_mtc_crew', 'scope' => 'status_data = 1', 'level' => null],
            'foreman' => ['table' => 'tb_users_mtc_fm', 'id' => '_id_mtc_fm', 'reference' => '_id_mtc_fm', 'scope' => 'level_access = 0 AND status_data = 1', 'level' => 0],
            'admin' => ['table' => 'tb_users_mtc_fm', 'id' => '_id_mtc_fm', 'reference' => '_id_mtc_fm', 'scope' => 'level_access = 1 AND status_data = 1', 'level' => 1],
            'superadmin' => ['table' => 'tb_users_mtc_fm', 'id' => '_id_mtc_fm', 'reference' => '_id_mtc_fm', 'scope' => 'level_access = 2 AND status_data = 1', 'level' => 2],
            default => ['table' => '', 'id' => '', 'reference' => '', 'scope' => '1 = 0', 'level' => null],
        };
    }

    private function canManageRole(string $role, array $actor): bool
    {
        return $actor['role'] === 'superadmin' && $this->userTable($role)['table'] !== '';
    }

    private function canViewRole(string $role, array $actor): bool
    {
        if ($this->userTable($role)['table'] === '') return false;
        if ($actor['role'] === 'superadmin') return true;
        return $actor['role'] === 'admin' && in_array($role, ['mechanic', 'foreman'], true);
    }

    private function userScope(array $meta, string $role, array $actor, array &$params): string
    {
        $scope = $meta['scope'];
        if ($actor['role'] === 'admin') {
            if ($role === 'foreman') {
                $scope .= " AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites afjs WHERE afjs._id_mtc_fm = {$meta['table']}.{$meta['id']} AND afjs.job_site_id = :actorSite)";
            } else {
                $scope .= ' AND job_site_id = :actorSite';
            }
            $params['actorSite'] = (int) $actor['jobSiteId'];
        }
        return $scope;
    }

    /** @return list<array{id:int,code:string,name:string}> */
    private function siteOptions(PDO $db, bool $activeOnly = true): array
    {
        $query = $db->query('SELECT id, code, name FROM tb_job_sites' . ($activeOnly ? ' WHERE is_active = 1' : '') . ' ORDER BY name');
        return $query->fetchAll();
    }

    public function users(): void
    {
        $db = $this->db(); if (!$db) return;
        $role = (string) ($_GET['role'] ?? 'mechanic');
        $meta = $this->userTable($role);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Role tidak valid']], 422); return; }
        $actor = $_SESSION['dmar_user'];
        if (!$this->canViewRole($role, $actor)) { Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Anda tidak memiliki akses untuk melihat role tersebut']], 403); return; }
        $search = trim((string) ($_GET['search'] ?? ''));
        $searchBy = (string) ($_GET['searchBy'] ?? 'name');
        if (!in_array($searchBy, ['name', 'nrpp', 'position'], true)) $searchBy = 'name';
        $limit = max(1, min(500, (int) ($_GET['limit'] ?? 500)));
        $offset = max(0, (int) ($_GET['offset'] ?? 0));
        $where = $meta['scope'];
        $params = [];
        if ($actor['role'] === 'admin' && $role === 'foreman') {
            $where .= ' AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites afjs WHERE afjs._id_mtc_fm = u._id_mtc_fm AND afjs.job_site_id = :actorSite)';
            $params['actorSite'] = (int) $actor['jobSiteId'];
        } elseif ($actor['role'] === 'admin') {
            $where .= ' AND u.job_site_id = :actorSite';
            $params['actorSite'] = (int) $actor['jobSiteId'];
        } elseif (isset($_GET['jobSiteId']) && (int) $_GET['jobSiteId'] > 0) {
            $where .= $role === 'foreman'
                ? ' AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites sfjs WHERE sfjs._id_mtc_fm = u._id_mtc_fm AND sfjs.job_site_id = :site)'
                : ' AND u.job_site_id = :site';
            $params['site'] = (int) $_GET['jobSiteId'];
        }
        if ($search !== '') {
            $searchColumn = match ($searchBy) {
                'nrpp' => 'u.nrpp',
                'position' => 'u.jabatan',
                default => 'u.nama',
            };
            $where .= " AND {$searchColumn} LIKE :searchValue";
            $params['searchValue'] = '%' . mb_substr($search, 0, 100) . '%';
        }
        try {
            $level = $meta['level'] === null ? '0 AS levelAccess' : 'u.level_access AS levelAccess';
            $assignmentSelect = $role === 'foreman'
                ? ",(SELECT GROUP_CONCAT(fjs.job_site_id ORDER BY fjs.job_site_id) FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteIds, (SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames"
                : ', NULL AS assignedJobSiteIds, NULL AS assignedJobSiteNames';
            $profileSelect = ', u.profile_image_path AS profileImagePath';
            $countQuery = $db->prepare("SELECT COUNT(*) FROM {$meta['table']} u WHERE {$where}");
            $countQuery->execute($params);
            $total = (int) $countQuery->fetchColumn();
            $query = $db->prepare("SELECT u.{$meta['id']} AS id, u.nrpp, u.nama AS name, u.jabatan AS position, {$level}, u.job_site_id AS jobSiteId, js.name AS jobSiteName{$assignmentSelect}{$profileSelect} FROM {$meta['table']} u LEFT JOIN tb_job_sites js ON js.id = u.job_site_id WHERE {$where} ORDER BY u.nama LIMIT :limit OFFSET :offset");
            foreach ($params as $key => $value) $query->bindValue(':' . $key, $value);
            $query->bindValue(':limit', $limit, PDO::PARAM_INT);
            $query->bindValue(':offset', $offset, PDO::PARAM_INT);
            $query->execute();
            $items = $query->fetchAll();
            foreach ($items as &$item) {
                $item['profileImageUrl'] = ImageUploadMiddleware::url($item['profileImagePath'] ?? null);
                unset($item['profileImagePath']);
            }
            unset($item);
            if ($role === 'foreman') {
                foreach ($items as &$item) {
                    $item['jobSiteIds'] = $item['assignedJobSiteIds'] ? array_map('intval', explode(',', (string) $item['assignedJobSiteIds'])) : [];
                    $item['jobSiteNames'] = $item['assignedJobSiteNames'] ? explode(' · ', (string) $item['assignedJobSiteNames']) : [];
                    $item['jobSiteName'] = $item['assignedJobSiteNames'];
                    unset($item['assignedJobSiteIds'], $item['assignedJobSiteNames']);
                }
                unset($item);
            }
            $sites = $this->siteOptions($db);
            if ($actor['role'] === 'admin') {
                $sites = array_values(array_filter($sites, static fn (array $site): bool => (int) $site['id'] === (int) $actor['jobSiteId']));
            }
            Response::json(['ok' => true, 'data' => ['items' => $items, 'total' => $total, 'role' => $role, 'jobSites' => $sites]]);
        } catch (Throwable $error) {
            error_log('DMAR admin users list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar pengguna tidak tersedia']], 503);
        }
    }

    public function createUser(): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $role = (string) ($input['role'] ?? '');
        $meta = $this->userTable($role);
        $actor = $_SESSION['dmar_user'];
        $nrpp = trim((string) ($input['nrpp'] ?? ''));
        $name = trim((string) ($input['name'] ?? ''));
        $position = trim((string) ($input['position'] ?? ''));
        $password = (string) ($input['password'] ?? '');
        if (!$this->canManageRole($role, $actor)) { Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Anda tidak memiliki akses untuk menambahkan role tersebut']], 403); return; }
        if ($meta['table'] === '' || $nrpp === '' || $name === '' || $password === '' || strlen($nrpp) > 100 || strlen($name) > 100 || strlen($position) > 25 || strlen($password) < 8) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'NRPP, nama, password minimal 8 karakter, dan jabatan valid wajib diisi']], 422); return;
        }
        $foremanSiteIds = [];
        if ($role === 'foreman') {
            $rawSiteIds = $input['jobSiteIds'] ?? [];
            if (!is_array($rawSiteIds)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Daftar job site foreman tidak valid']], 422); return; }
            foreach ($rawSiteIds as $rawSiteId) {
                if (filter_var($rawSiteId, FILTER_VALIDATE_INT) === false || (int) $rawSiteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Job site foreman tidak valid']], 422); return; }
                $foremanSiteIds[] = (int) $rawSiteId;
            }
            $foremanSiteIds = array_values(array_unique($foremanSiteIds));
            if ($foremanSiteIds === []) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Pilih minimal satu job site untuk foreman']], 422); return; }
        }
        $siteId = $role === 'foreman'
            ? ($foremanSiteIds[0] ?? 0)
            : ($actor['role'] === 'admin' ? (int) $actor['jobSiteId'] : (int) ($input['jobSiteId'] ?? 0));
        if ($role === 'superadmin') $siteId = 0;
        if ($role !== 'superadmin' && $siteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Pilih job site untuk pengguna baru']], 422); return; }
        $imagePath = null;
        try {
            $sitesToCheck = $role === 'foreman' ? $foremanSiteIds : ($siteId > 0 ? [$siteId] : []);
            if ($sitesToCheck !== []) {
                $siteCheck = $db->prepare('SELECT COUNT(*) FROM tb_job_sites WHERE is_active = 1 AND id IN (' . implode(',', array_map('intval', $sitesToCheck)) . ')');
                $siteCheck->execute();
                if ((int) $siteCheck->fetchColumn() !== count($sitesToCheck)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Satu atau beberapa job site tidak ditemukan atau tidak aktif']], 422); return; }
            }
            $duplicate = $db->prepare("SELECT 1 FROM {$meta['table']} WHERE nrpp = :nrpp LIMIT 1");
            $duplicate->execute(['nrpp' => $nrpp]);
            if ($duplicate->fetchColumn()) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'NRPP sudah digunakan pada kelompok akun ini']], 409); return; }
            if ($role === 'mechanic' && isset($_FILES['profileImage'])) {
                try { $imagePath = (new ImageUploadMiddleware())->storeWebp($_FILES['profileImage'], 'profiles'); }
                catch (RuntimeException $error) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $error->getMessage()]], 422); return; }
            }
            $level = $meta['level'] ?? 0;
            if (in_array($role, ['admin', 'superadmin'], true) && $position === '') $position = $role;
            $db->beginTransaction();
            $imageColumn = $role === 'mechanic' ? ', profile_image_path' : '';
            $imageValue = $role === 'mechanic' ? ', :imagePath' : '';
            $query = $db->prepare("INSERT INTO {$meta['table']} (nrpp, nama, jabatan, password, level_access, job_site_id{$imageColumn}) VALUES (:nrpp, :name, :position, :password, :level, :site{$imageValue})");
            $insertValues = ['nrpp' => $nrpp, 'name' => $name, 'position' => $position, 'password' => password_hash($password, PASSWORD_DEFAULT), 'level' => $level, 'site' => $siteId > 0 ? $siteId : null];
            if ($role === 'mechanic') $insertValues['imagePath'] = $imagePath;
            $query->execute($insertValues);
            $newId = (int) $db->lastInsertId();
            if ($role === 'foreman') {
                $assign = $db->prepare('INSERT INTO tb_users_mtc_fm_job_sites (_id_mtc_fm, job_site_id) VALUES (:id, :site)');
                foreach ($foremanSiteIds as $foremanSiteId) $assign->execute(['id' => $newId, 'site' => $foremanSiteId]);
            }
            $db->commit();
            Response::json(['ok' => true, 'data' => ['id' => $newId]], 201);
        } catch (Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            ImageUploadMiddleware::delete($imagePath);
            error_log('DMAR admin create user failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Pengguna gagal ditambahkan']], 503);
        }
    }

    public function updateUser(string $role, string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $meta = $this->userTable($role);
        $actor = $_SESSION['dmar_user'];
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Role tidak valid']], 422); return; }
        if (!$this->canManageRole($role, $actor)) { Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Anda tidak memiliki akses untuk mengubah pengguna tersebut']], 403); return; }
        $newImagePath = null;
        $oldImagePath = null;
        $fields = [];
        $params = ['id' => (int) $id];
        foreach (['nrpp' => ['nrpp', 100], 'name' => ['nama', 100], 'position' => ['jabatan', 25]] as $key => [$column, $max]) {
            if (!array_key_exists($key, $input)) continue;
            $value = trim((string) $input[$key]);
            if (($value === '' && $key !== 'position') || strlen($value) > $max) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Field pengguna tidak valid']], 422); return; }
            $fields[] = "{$column} = :{$key}"; $params[$key] = $value;
        }
        $foremanSiteIds = null;
        if ($role === 'foreman' && array_key_exists('jobSiteIds', $input)) {
            if (!is_array($input['jobSiteIds'])) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Daftar job site foreman tidak valid']], 422); return; }
            $foremanSiteIds = [];
            foreach ($input['jobSiteIds'] as $rawSiteId) {
                if (filter_var($rawSiteId, FILTER_VALIDATE_INT) === false || (int) $rawSiteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Job site foreman tidak valid']], 422); return; }
                $foremanSiteIds[] = (int) $rawSiteId;
            }
            $foremanSiteIds = array_values(array_unique($foremanSiteIds));
            if ($foremanSiteIds === []) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Pilih minimal satu job site untuk foreman']], 422); return; }
            $siteCheck = $db->prepare('SELECT COUNT(*) FROM tb_job_sites WHERE is_active = 1 AND id IN (' . implode(',', array_map('intval', $foremanSiteIds)) . ')');
            $siteCheck->execute();
            if ((int) $siteCheck->fetchColumn() !== count($foremanSiteIds)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Satu atau beberapa job site tidak ditemukan atau tidak aktif']], 422); return; }
            $fields[] = 'job_site_id = :primaryForemanSite';
            $params['primaryForemanSite'] = $foremanSiteIds[0];
        }
        if ($actor['role'] === 'superadmin' && array_key_exists('jobSiteId', $input)) {
            $siteId = ($role === 'superadmin' && ($input['jobSiteId'] === null || (int) $input['jobSiteId'] === 0)) ? null : (int) $input['jobSiteId'];
            if ($siteId !== null) {
                $siteCheck = $db->prepare('SELECT 1 FROM tb_job_sites WHERE id = :id AND is_active = 1');
                $siteCheck->execute(['id' => $siteId]);
                if (!$siteCheck->fetchColumn()) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Job site tidak ditemukan atau tidak aktif']], 422); return; }
            } elseif ($role !== 'superadmin') { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Role selain superadmin wajib memiliki job site']], 422); return; }
            $fields[] = 'job_site_id = :jobSiteId';
            $params['jobSiteId'] = $siteId;
        }
        if (!$fields) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Tidak ada perubahan yang dikirim']], 422); return; }
        if (isset($params['nrpp'])) {
            $duplicate = $db->prepare("SELECT 1 FROM {$meta['table']} WHERE nrpp = :nrpp AND {$meta['id']} <> :id LIMIT 1");
            $duplicate->execute(['nrpp' => $params['nrpp'], 'id' => (int) $id]);
            if ($duplicate->fetchColumn()) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'NRPP sudah digunakan']], 409); return; }
        }
        $scopeParams = [];
        $scope = $this->userScope($meta, $role, $actor, $scopeParams);
        $params += $scopeParams;
        if ($role === 'mechanic' && isset($_FILES['profileImage'])) {
            try { $newImagePath = (new ImageUploadMiddleware())->storeWebp($_FILES['profileImage'], 'profiles'); }
            catch (RuntimeException $error) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $error->getMessage()]], 422); return; }
            try {
                $oldQuery = $db->prepare('SELECT profile_image_path FROM tb_users_mtc_crew WHERE _id_mtc_crew = :id');
                $oldQuery->execute(['id' => (int) $id]);
                $old = $oldQuery->fetchColumn();
            } catch (Throwable $error) {
                ImageUploadMiddleware::delete($newImagePath);
                error_log('DMAR mechanic profile image lookup failed: ' . $error->getMessage());
                Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Foto profil lama gagal diperiksa. Coba lagi beberapa saat.']], 503);
                return;
            }
            $oldImagePath = is_string($old) ? $old : null;
            $fields[] = 'profile_image_path = :imagePath';
            $params['imagePath'] = $newImagePath;
        }
        $committed = false;
        try {
            $db->beginTransaction();
            $query = $db->prepare("UPDATE {$meta['table']} SET " . implode(', ', $fields) . " WHERE {$meta['id']} = :id AND {$scope}");
            $query->execute($params);
            if ($query->rowCount() === 0 && !$this->userExists($db, $meta, (int) $id, $role, $actor)) { $db->rollBack(); ImageUploadMiddleware::delete($newImagePath); Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Pengguna tidak ditemukan']], 404); return; }
            if ($foremanSiteIds !== null) {
                $deleteAssignments = $db->prepare('DELETE FROM tb_users_mtc_fm_job_sites WHERE _id_mtc_fm = :id');
                $deleteAssignments->execute(['id' => (int) $id]);
                $insertAssignment = $db->prepare('INSERT INTO tb_users_mtc_fm_job_sites (_id_mtc_fm, job_site_id) VALUES (:id, :site)');
                foreach ($foremanSiteIds as $foremanSiteId) $insertAssignment->execute(['id' => (int) $id, 'site' => $foremanSiteId]);
            }
            $db->commit();
            $committed = true;
            if ($newImagePath !== null) ImageUploadMiddleware::delete($oldImagePath);
            if ($meta['level'] !== null && $actor['role'] === 'superadmin') {
                RememberMe::revokeUser($db, 'staff', (int) $id);
            } elseif ($role === 'mechanic' && $actor['role'] === 'superadmin') {
                RememberMe::revokeUser($db, 'mekanik', (int) $id);
            }
            Response::json(['ok' => true, 'data' => ['updated' => true]]);
        } catch (Throwable $error) {
            if (!$committed) ImageUploadMiddleware::delete($newImagePath);
            error_log('DMAR admin update user failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Pengguna gagal diperbarui']], 503);
        }
    }

    private function userExists(PDO $db, array $meta, int $id, string $role, array $actor): bool
    {
        $params = ['id' => $id];
        $scope = $this->userScope($meta, $role, $actor, $params);
        $query = $db->prepare("SELECT 1 FROM {$meta['table']} WHERE {$meta['id']} = :id AND {$scope}");
        $query->execute($params);
        return (bool) $query->fetchColumn();
    }

    public function resetPassword(string $role, string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(); if (!$db) return;
        $meta = $this->userTable($role);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Role tidak valid']], 422); return; }
        $actor = $_SESSION['dmar_user'];
        if (!$this->canManageRole($role, $actor)) { Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Anda tidak memiliki akses untuk reset akun tersebut']], 403); return; }
        try {
            $idParams = ['id' => (int) $id];
            $scope = $this->userScope($meta, $role, $actor, $idParams);
            $lookup = $db->prepare("SELECT nrpp FROM {$meta['table']} WHERE {$meta['id']} = :id AND {$scope} LIMIT 1");
            $lookup->execute($idParams);
            $nrpp = $lookup->fetchColumn();
            if (!is_string($nrpp) || trim($nrpp) === '') { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Pengguna tidak ditemukan']], 404); return; }

            $resetPassword = trim($nrpp);
            $params = ['password' => password_hash($resetPassword, PASSWORD_DEFAULT), 'id' => (int) $id, 'nrpp' => $nrpp];
            $scope = $this->userScope($meta, $role, $actor, $params);
            $query = $db->prepare("UPDATE {$meta['table']} SET password = :password WHERE {$meta['id']} = :id AND nrpp = :nrpp AND {$scope}");
            $query->execute($params);
            RememberMe::revokeUser($db, $role === 'mechanic' ? 'mekanik' : 'staff', (int) $id);
            Response::json(['ok' => true, 'data' => ['passwordReset' => true]]);
        } catch (Throwable $error) {
            error_log('DMAR admin reset password failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Reset password gagal']], 503);
        }
    }

    public function deleteUser(string $role, string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(); if (!$db) return;
        $meta = $this->userTable($role);
        $userId = (int) $id;
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Role tidak valid']], 422); return; }
        $current = $_SESSION['dmar_user'];
        if (!$this->canManageRole($role, $current)) { Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Anda tidak memiliki akses untuk menghapus pengguna tersebut']], 403); return; }
        if ($role !== 'mechanic' && $current['id'] === $userId) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Admin yang sedang login tidak dapat menghapus akunnya sendiri']], 409); return; }
        try {
            if (!$this->userExists($db, $meta, $userId, $role, $current)) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Pengguna tidak ditemukan']], 404); return; }
            if ($role === 'superadmin') {
                $admins = (int) $db->query('SELECT COUNT(*) FROM tb_users_mtc_fm WHERE level_access = 2 AND status_data = 1')->fetchColumn();
                if ($admins <= 1) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Superadmin terakhir tidak dapat dihapus']], 409); return; }
            }
            $params = ['id' => $userId];
            $scope = $this->userScope($meta, $role, $current, $params);
            $query = $db->prepare("UPDATE {$meta['table']} SET status_data = 0 WHERE {$meta['id']} = :id AND {$scope}");
            $query->execute($params);
            if ($query->rowCount() !== 1) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Pengguna tidak ditemukan']], 404); return; }
            RememberMe::revokeUser($db, $role === 'mechanic' ? 'mekanik' : 'staff', $userId);
            Response::json(['ok' => true, 'data' => ['deleted' => true, 'statusData' => false]]);
        } catch (Throwable $error) {
            error_log('DMAR admin delete user failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Pengguna gagal dihapus']], 503);
        }
    }

    private function master(string $resource): array
    {
        return match ($resource) {
            'units' => ['table' => 'tb_master_unit', 'fields' => ['unitCode' => ['unit_code', 10], 'model' => ['model', 25], 'brand' => ['brand', 30]], 'select' => '_id AS id, unit_code AS unitCode, model, brand, image_path AS imagePath'],
            'job-codes' => ['table' => 'tb_master_codejob', 'fields' => ['description' => ['description', 50], 'groupCode' => ['group_code', 0]], 'select' => '_id AS id, description, group_code AS groupCode'],
            'components' => ['table' => 'tb_master_component', 'fields' => ['description' => ['description', 50]], 'select' => '_id AS id, description, group_code AS groupCode'],
            default => ['table' => '', 'fields' => [], 'select' => ''],
        };
    }

    public function masters(string $resource): void
    {
        $db = $this->db(true); if (!$db) return;
        $meta = $this->master($resource);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Data master tidak ditemukan']], 404); return; }
        $params = [];
        $where = $resource === 'units' ? 'status_data = 1' : '1 = 1';
        if ($resource === 'job-codes' && isset($_GET['groupCode']) && in_array((int) $_GET['groupCode'], [1, 2], true)) { $where .= ' AND group_code = :group'; $params['group'] = (int) $_GET['groupCode']; }
        $limit = 1000;
        $offset = 0;
        if ($resource === 'units') {
            $searchBy = (string) ($_GET['searchBy'] ?? 'unitCode');
            $searchColumn = match ($searchBy) {
                'model' => 'model',
                'brand' => 'brand',
                default => 'unit_code',
            };
            $search = trim((string) ($_GET['search'] ?? ''));
            if ($search !== '') {
                $where .= " AND {$searchColumn} LIKE :search";
                $params['search'] = '%' . mb_substr($search, 0, 100) . '%';
            }
            $limit = max(1, min(100, (int) ($_GET['limit'] ?? 10)));
            $offset = max(0, (int) ($_GET['offset'] ?? 0));
        }
        try {
            $orderBy = '_id';
            $countQuery = $db->prepare("SELECT COUNT(*) FROM {$meta['table']} WHERE {$where}");
            $countQuery->execute($params);
            $total = (int) $countQuery->fetchColumn();
            $query = $db->prepare("SELECT {$meta['select']} FROM {$meta['table']} WHERE {$where} ORDER BY {$orderBy} ASC LIMIT :limit OFFSET :offset");
            foreach ($params as $key => $value) $query->bindValue(':' . $key, $value);
            $query->bindValue(':limit', $limit, PDO::PARAM_INT);
            $query->bindValue(':offset', $offset, PDO::PARAM_INT);
            $query->execute();
            $items = $query->fetchAll();
            if ($resource === 'units') {
                foreach ($items as &$item) {
                    $item['imageUrl'] = ImageUploadMiddleware::url($item['imagePath'] ?? null);
                    unset($item['imagePath']);
                }
                unset($item);
            }
            Response::json(['ok' => true, 'data' => ['items' => $items, 'total' => $total, 'resource' => $resource]]);
        } catch (Throwable $error) {
            error_log('DMAR admin master list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Data master tidak tersedia']], 503);
        }
    }

    public function createMaster(string $resource): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(true); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $meta = $this->master($resource);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Data master tidak ditemukan']], 404); return; }
        $values = $this->masterValues($resource, $input);
        if ($values === null) return;
        $imagePath = null;
        try {
            if ($this->masterDuplicate($db, $resource, $values)) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Item data master tersebut sudah ada']], 409); return; }
            if ($resource === 'units' && isset($_FILES['unitImage'])) {
                try { $imagePath = (new ImageUploadMiddleware())->storeWebp($_FILES['unitImage'], 'units'); }
                catch (RuntimeException $error) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $error->getMessage()]], 422); return; }
            }
            $columns = []; $placeholders = []; $params = [];
            foreach ($values as $key => $value) { $column = $meta['fields'][$key][0]; $columns[] = $column; $placeholders[] = ':' . $key; $params[$key] = $value; }
            if ($resource === 'units' && $imagePath !== null) { $columns[] = 'image_path'; $placeholders[] = ':imagePath'; $params['imagePath'] = $imagePath; }
            if ($resource === 'components') { $columns[] = 'group_code'; $placeholders[] = '1'; }
            $query = $db->prepare("INSERT INTO {$meta['table']} (" . implode(', ', $columns) . ') VALUES (' . implode(', ', $placeholders) . ')');
            $query->execute($params);
            Response::json(['ok' => true, 'data' => ['id' => (int) $db->lastInsertId()]], 201);
        } catch (Throwable $error) {
            ImageUploadMiddleware::delete($imagePath);
            error_log('DMAR admin create master failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Data master gagal ditambahkan']], 503);
        }
    }

    /** @return array<string, string|int>|null */
    private function masterValues(string $resource, array $input): ?array
    {
        $meta = $this->master($resource); $values = [];
        foreach ($meta['fields'] as $key => [$column, $max]) {
            if (!array_key_exists($key, $input)) continue;
            if ($key === 'groupCode') {
                $group = filter_var($input[$key], FILTER_VALIDATE_INT);
                if (!in_array($group, [1, 2], true)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kelompok Code Job tidak valid']], 422); return null; }
                $values[$key] = $group; continue;
            }
            $value = trim((string) $input[$key]);
            if ($value === '' || strlen($value) > $max) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Deskripsi data master wajib diisi dan tidak boleh terlalu panjang']], 422); return null; }
            $values[$key] = $value;
        }
        if (!$values || ($resource === 'units' && count($values) !== 3) || ($resource === 'job-codes' && !isset($values['description'], $values['groupCode'])) || ($resource === 'components' && !isset($values['description']))) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Field data master belum lengkap']], 422); return null;
        }
        return $values;
    }

    public function updateMaster(string $resource, string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(true); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $meta = $this->master($resource);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Data master tidak ditemukan']], 404); return; }
        $values = $this->masterValues($resource, $input);
        if ($values === null) return;
        $newImagePath = null;
        $oldImagePath = null;
        try {
            if ($this->masterDuplicate($db, $resource, $values, (int) $id)) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Item data master tersebut sudah ada']], 409); return; }
            $sets = []; $params = ['id' => (int) $id];
            foreach ($values as $key => $value) { $sets[] = $meta['fields'][$key][0] . ' = :' . $key; $params[$key] = $value; }
            if ($resource === 'units' && isset($_FILES['unitImage'])) {
                try { $newImagePath = (new ImageUploadMiddleware())->storeWebp($_FILES['unitImage'], 'units'); }
                catch (RuntimeException $error) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $error->getMessage()]], 422); return; }
                $imageQuery = $db->prepare('SELECT image_path FROM tb_master_unit WHERE _id = :id AND status_data = 1');
                $imageQuery->execute(['id' => (int) $id]);
                $old = $imageQuery->fetchColumn();
                $oldImagePath = is_string($old) ? $old : null;
                $sets[] = 'image_path = :imagePath';
                $params['imagePath'] = $newImagePath;
            }
            $activeFilter = $resource === 'units' ? ' AND status_data = 1' : '';
            $query = $db->prepare("UPDATE {$meta['table']} SET " . implode(', ', $sets) . " WHERE _id = :id{$activeFilter}");
            $query->execute($params);
            if ($query->rowCount() === 0) {
                $exists = $db->prepare("SELECT 1 FROM {$meta['table']} WHERE _id = :id{$activeFilter}"); $exists->execute(['id' => (int) $id]);
                if (!$exists->fetchColumn()) { ImageUploadMiddleware::delete($newImagePath); Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Item data master tidak ditemukan']], 404); return; }
            }
            if ($newImagePath !== null) ImageUploadMiddleware::delete($oldImagePath);
            Response::json(['ok' => true, 'data' => ['updated' => true]]);
        } catch (Throwable $error) {
            ImageUploadMiddleware::delete($newImagePath);
            error_log('DMAR admin update master failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Data master gagal diperbarui']], 503);
        }
    }

    public function deleteMaster(string $resource, string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(true); if (!$db) return;
        $meta = $this->master($resource);
        if ($meta['table'] === '') { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Data master tidak ditemukan']], 404); return; }
        try {
            $activeFilter = $resource === 'units' ? ' AND status_data = 1' : '';
            $selected = $db->prepare("SELECT * FROM {$meta['table']} WHERE _id = :id{$activeFilter}"); $selected->execute(['id' => (int) $id]); $item = $selected->fetch();
            if (!$item) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Item data master tidak ditemukan']], 404); return; }
            if ($resource === 'units') {
                $query = $db->prepare('UPDATE tb_master_unit SET status_data = 0 WHERE _id = :id AND status_data = 1');
                $query->execute(['id' => (int) $id]);
                if ($query->rowCount() !== 1) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Populasi unit tidak ditemukan']], 404); return; }
            } else {
                [$reportColumn, $valueColumn] = match ($resource) { 'job-codes' => ['code_job', 'description'], default => ['component', 'description'] };
                $usage = $db->prepare("SELECT (SELECT COUNT(*) FROM tb_dmar_v2 WHERE {$reportColumn} = :newValue) + (SELECT COUNT(*) FROM tb_dmar WHERE {$reportColumn} = :legacyValue)"); $usage->execute(['newValue' => $item[$valueColumn], 'legacyValue' => $item[$valueColumn]]);
                if ((int) $usage->fetchColumn() > 0) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Item ini dipakai laporan DMAR dan tidak dapat dihapus']], 409); return; }
                $query = $db->prepare("DELETE FROM {$meta['table']} WHERE _id = :id"); $query->execute(['id' => (int) $id]);
            }
            Response::json(['ok' => true, 'data' => ['deleted' => true, 'statusData' => $resource === 'units' ? false : null]]);
        } catch (Throwable $error) {
            error_log('DMAR admin delete master failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Data master gagal dihapus']], 503);
        }
    }

    public function jobSites(): void
    {
        $db = $this->db(true); if (!$db) return;
        try {
            $query = $db->query('SELECT s.id, s.code, s.name, s.is_active AS isActive, s.created_at AS createdAt, (SELECT COUNT(*) FROM tb_users_mtc_crew c WHERE c.job_site_id = s.id AND c.status_data = 1) + (SELECT COUNT(*) FROM tb_users_mtc_fm f WHERE f.level_access <> 0 AND f.job_site_id = s.id AND f.status_data = 1) + (SELECT COUNT(*) FROM tb_users_mtc_fm_job_sites fs INNER JOIN tb_users_mtc_fm af ON af._id_mtc_fm = fs._id_mtc_fm AND af.status_data = 1 WHERE fs.job_site_id = s.id) AS userCount, (SELECT COUNT(*) FROM tb_dmar_v2 d WHERE d.job_site_id = s.id) AS reportCount FROM tb_job_sites s ORDER BY s.name');
            Response::json(['ok' => true, 'data' => ['items' => $query->fetchAll()]]);
        } catch (Throwable $error) {
            error_log('DMAR job site list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar job site tidak tersedia']], 503);
        }
    }

    public function createJobSite(): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(true); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $code = strtoupper(trim((string) ($input['code'] ?? '')));
        $name = trim((string) ($input['name'] ?? ''));
        if (!preg_match('/^[A-Z0-9][A-Z0-9_-]{0,29}$/', $code) || $name === '' || strlen($name) > 100) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kode job site hanya boleh berisi huruf, angka, tanda hubung, atau garis bawah; nama wajib diisi']], 422); return;
        }
        try {
            $duplicate = $db->prepare('SELECT 1 FROM tb_job_sites WHERE code = :code OR name = :name LIMIT 1');
            $duplicate->execute(['code' => $code, 'name' => $name]);
            if ($duplicate->fetchColumn()) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Kode atau nama job site sudah digunakan']], 409); return; }
            $query = $db->prepare('INSERT INTO tb_job_sites (code, name, is_active) VALUES (:code, :name, 1)');
            $query->execute(['code' => $code, 'name' => $name]);
            Response::json(['ok' => true, 'data' => ['id' => (int) $db->lastInsertId()]], 201);
        } catch (Throwable $error) {
            error_log('DMAR job site create failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Job site gagal ditambahkan']], 503);
        }
    }

    public function updateJobSite(string $id): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(true); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $siteId = (int) $id;
        $selected = $db->prepare('SELECT id, code, name, is_active FROM tb_job_sites WHERE id = :id');
        $selected->execute(['id' => $siteId]);
        $current = $selected->fetch();
        if (!$current) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Job site tidak ditemukan']], 404); return; }

        $code = strtoupper(trim((string) ($input['code'] ?? $current['code'])));
        $name = trim((string) ($input['name'] ?? $current['name']));
        $isActive = array_key_exists('isActive', $input) ? (bool) $input['isActive'] : (bool) $current['is_active'];
        if (!preg_match('/^[A-Z0-9][A-Z0-9_-]{0,29}$/', $code) || $name === '' || strlen($name) > 100) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Data job site tidak valid']], 422); return;
        }
        try {
            if (!$isActive && (bool) $current['is_active']) {
            $usage = $db->prepare('SELECT (SELECT COUNT(*) FROM tb_users_mtc_crew WHERE job_site_id = :crewSite AND status_data = 1) + (SELECT COUNT(*) FROM tb_users_mtc_fm WHERE level_access <> 0 AND job_site_id = :fmSite AND status_data = 1) + (SELECT COUNT(*) FROM tb_users_mtc_fm_job_sites fs INNER JOIN tb_users_mtc_fm f ON f._id_mtc_fm = fs._id_mtc_fm AND f.status_data = 1 WHERE fs.job_site_id = :foremanSite) AS total');
            $usage->execute(['crewSite' => $siteId, 'fmSite' => $siteId, 'foremanSite' => $siteId]);
                if ((int) $usage->fetchColumn() > 0) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Pindahkan seluruh pengguna ke site lain sebelum menonaktifkan job site']], 409); return; }
            }
            $duplicate = $db->prepare('SELECT 1 FROM tb_job_sites WHERE id <> :id AND (code = :code OR name = :name) LIMIT 1');
            $duplicate->execute(['id' => $siteId, 'code' => $code, 'name' => $name]);
            if ($duplicate->fetchColumn()) { Response::json(['ok' => false, 'error' => ['code' => 'conflict', 'message' => 'Kode atau nama job site sudah digunakan']], 409); return; }
            $query = $db->prepare('UPDATE tb_job_sites SET code = :code, name = :name, is_active = :active WHERE id = :id');
            $query->execute(['code' => $code, 'name' => $name, 'active' => $isActive ? 1 : 0, 'id' => $siteId]);
            Response::json(['ok' => true, 'data' => ['updated' => true]]);
        } catch (Throwable $error) {
            error_log('DMAR job site update failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Job site gagal diperbarui']], 503);
        }
    }

    private function masterDuplicate(PDO $db, string $resource, array $values, ?int $exceptId = null): bool
    {
        if ($resource === 'units') {
            $sql = 'SELECT 1 FROM tb_master_unit WHERE unit_code = :value';
            $params = ['value' => $values['unitCode']];
        } elseif ($resource === 'job-codes') {
            $sql = 'SELECT 1 FROM tb_master_codejob WHERE description = :value AND group_code = :groupCode';
            $params = ['value' => $values['description'], 'groupCode' => $values['groupCode']];
        } else {
            $sql = 'SELECT 1 FROM tb_master_component WHERE description = :value';
            $params = ['value' => $values['description']];
        }
        if ($exceptId !== null) { $sql .= ' AND _id <> :exceptId'; $params['exceptId'] = $exceptId; }
        $query = $db->prepare($sql . ' LIMIT 1'); $query->execute($params);
        return (bool) $query->fetchColumn();
    }

    public function approvedReports(): void
    {
        $db = $this->db(); if (!$db) return;
        $limit = min(500, max(1, (int) ($_GET['limit'] ?? 50))); $offset = max(0, (int) ($_GET['offset'] ?? 0));
        $mechanicField = (string) ($_GET['mechanicField'] ?? 'name');
        if (!in_array($mechanicField, ['name', 'nrpp'], true)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kolom pencarian mekanik tidak valid']], 422); return; }
        $mechanicSearch = trim((string) ($_GET['mechanicSearch'] ?? ''));
        $unitCode = trim((string) ($_GET['unitCode'] ?? ''));
        $from = trim((string) ($_GET['from'] ?? '')); $to = trim((string) ($_GET['to'] ?? ''));
        $foremanInput = trim((string) ($_GET['foremanId'] ?? ''));
        $where = ['d.status_dmar = 1']; $params = [];
        $actor = $_SESSION['dmar_user'];
        if ($actor['role'] === 'admin') {
            $where[] = 'd.job_site_id = :actorSite';
            $params['actorSite'] = (int) $actor['jobSiteId'];
        } elseif (isset($_GET['jobSiteId']) && (int) $_GET['jobSiteId'] > 0) {
            $where[] = 'd.job_site_id = :site';
            $params['site'] = (int) $_GET['jobSiteId'];
        }
        if ($unitCode !== '') { $where[] = 'd.unit_code = :unitCode'; $params['unitCode'] = $unitCode; }
        if ($foremanInput !== '') {
            if (!ctype_digit($foremanInput) || (int) $foremanInput < 1) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Foreman tidak valid']], 422); return; }
            $where[] = 'd._id_mtc_fm = :foremanId AND fm.level_access = 0 AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = fm._id_mtc_fm AND fjs.job_site_id = d.job_site_id)';
            $params['foremanId'] = (int) $foremanInput;
        }
        if ($from !== '') { if (!$this->validDate($from)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Tanggal awal tidak valid']], 422); return; } $where[] = 'd.tgl >= :fromDate'; $params['fromDate'] = $from; }
        if ($to !== '') { if (!$this->validDate($to)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Tanggal akhir tidak valid']], 422); return; } $where[] = 'd.tgl <= :toDate'; $params['toDate'] = $to; }
        if ($mechanicSearch !== '') {
            $mechanicColumn = $mechanicField === 'nrpp' ? 'c.nrpp' : 'c.nama';
            $where[] = "{$mechanicColumn} LIKE :mechanicSearch";
            $params['mechanicSearch'] = '%' . $mechanicSearch . '%';
        }
        $clause = implode(' AND ', $where);
        try {
            $count = $db->prepare("SELECT COUNT(*) FROM tb_dmar_v2 d LEFT JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm WHERE {$clause}"); $count->execute($params);
            $query = $db->prepare("SELECT d.id_dmar_report AS id, d._id_mtc_fm AS foremanId, d.job_site_id AS jobSiteId, js.name AS jobSiteName, d.tgl AS date, d.unit_code AS unitCode, d.model, d.hm, d.problem, d.act_start AS `start`, d.act_end AS `finish`, d.code_job AS codeJob, d.status_unit AS unitStatus, d.component, d.remark, d.created_at AS createdAt, c.nrpp AS mechanicNrpp, c.nama AS mechanicName, fm.nama AS foremanName FROM tb_dmar_v2 d LEFT JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm LEFT JOIN tb_job_sites js ON js.id = d.job_site_id WHERE {$clause} ORDER BY d.tgl DESC, d.created_at DESC LIMIT {$limit} OFFSET {$offset}");
            $query->execute($params);
            $items = ReportActivities::attach($db, $query->fetchAll());
            Response::json(['ok' => true, 'data' => ['items' => $items, 'total' => (int) $count->fetchColumn(), 'limit' => $limit, 'offset' => $offset]]);
        } catch (Throwable $error) {
            error_log('DMAR admin approved reports failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Laporan approved sementara tidak tersedia']], 503);
        }
    }

    public function approvedUnitOptions(): void
    {
        $db = $this->db(); if (!$db) return;
        $actor = $_SESSION['dmar_user'];
        $where = ['d.status_dmar = 1']; $params = [];
        if ($actor['role'] === 'admin') {
            $where[] = 'd.job_site_id = :actorSite';
            $params['actorSite'] = (int) $actor['jobSiteId'];
        } elseif (isset($_GET['jobSiteId']) && (int) $_GET['jobSiteId'] > 0) {
            $where[] = 'd.job_site_id = :site';
            $params['site'] = (int) $_GET['jobSiteId'];
        }
        try {
            $query = $db->prepare('SELECT DISTINCT d.unit_code FROM tb_dmar_v2 d WHERE ' . implode(' AND ', $where) . ' AND d.unit_code IS NOT NULL AND d.unit_code <> \'\' ORDER BY d.unit_code');
            $query->execute($params);
            Response::json(['ok' => true, 'data' => ['items' => array_map('strval', $query->fetchAll(PDO::FETCH_COLUMN))]]);
        } catch (Throwable $error) {
            error_log('DMAR approved unit options failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar unit approved tidak tersedia']], 503);
        }
    }

    public function dashboard(): void
    {
        $db = $this->db(true); if (!$db) return;
        try {
            $userCounts = $db->query("SELECT (SELECT COUNT(*) FROM tb_users_mtc_crew WHERE status_data = 1) AS mechanics, (SELECT COUNT(*) FROM tb_users_mtc_fm WHERE level_access IN (0, 1) AND status_data = 1) AS staff, (SELECT COUNT(*) FROM tb_users_mtc_fm WHERE level_access = 2 AND status_data = 1) AS superadmins, (SELECT COUNT(*) FROM tb_job_sites WHERE is_active = 1) AS activeJobSites")->fetch();
            $statusCounts = $db->query('SELECT status_dmar AS status, COUNT(*) AS total FROM tb_dmar_v2 GROUP BY status_dmar')->fetchAll();
            $statusTotals = ['pending' => 0, 'approved' => 0, 'other' => 0];
            foreach ($statusCounts as $row) {
                $status = (int) $row['status']; $total = (int) $row['total'];
                if ($status === 0) $statusTotals['pending'] = $total;
                elseif ($status === 1) $statusTotals['approved'] = $total;
                else $statusTotals['other'] += $total;
            }

            $monthStart = new \DateTimeImmutable('first day of this month');
            $fromDate = $monthStart->modify('-5 months')->format('Y-m-d');
            $trendQuery = $db->prepare("SELECT DATE_FORMAT(tgl, '%Y-%m') AS month, COUNT(*) AS total, SUM(status_dmar = 1) AS approved, SUM(status_dmar = 0) AS pending FROM tb_dmar_v2 WHERE tgl >= :fromDate GROUP BY DATE_FORMAT(tgl, '%Y-%m') ORDER BY month");
            $trendQuery->execute(['fromDate' => $fromDate]);
            $trendRows = [];
            foreach ($trendQuery->fetchAll() as $row) $trendRows[(string) $row['month']] = ['total' => (int) $row['total'], 'approved' => (int) $row['approved'], 'pending' => (int) $row['pending']];
            $trend = [];
            for ($index = 5; $index >= 0; $index--) {
                $month = $monthStart->modify("-{$index} months")->format('Y-m');
                $trend[] = ['month' => $month, ...($trendRows[$month] ?? ['total' => 0, 'approved' => 0, 'pending' => 0])];
            }

            $siteQuery = $db->query('SELECT s.id, s.name, COUNT(d.id_dmar_report) AS reports FROM tb_job_sites s LEFT JOIN tb_dmar_v2 d ON d.job_site_id = s.id WHERE s.is_active = 1 GROUP BY s.id, s.name ORDER BY reports DESC, s.name LIMIT 8');
            $sites = array_map(static fn (array $row): array => ['id' => (int) $row['id'], 'name' => (string) $row['name'], 'reports' => (int) $row['reports']], $siteQuery->fetchAll());
            $totalReports = $statusTotals['pending'] + $statusTotals['approved'] + $statusTotals['other'];
            $unassignedReports = (int) $db->query('SELECT COUNT(*) FROM tb_dmar WHERE job_site_id IS NULL')->fetchColumn();

            Response::json(['ok' => true, 'data' => [
                'summary' => [
                    'totalReports' => $totalReports,
                    'pendingReports' => $statusTotals['pending'],
                    'approvedReports' => $statusTotals['approved'],
                    'otherReports' => $statusTotals['other'],
                    'unassignedReports' => $unassignedReports,
                    'mechanics' => (int) ($userCounts['mechanics'] ?? 0),
                    'staff' => (int) ($userCounts['staff'] ?? 0),
                    'superadmins' => (int) ($userCounts['superadmins'] ?? 0),
                    'activeJobSites' => (int) ($userCounts['activeJobSites'] ?? 0),
                ],
                'trend' => $trend,
                'sites' => $sites,
            ]]);
        } catch (Throwable $error) {
            error_log('DMAR superadmin dashboard failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Ringkasan dashboard sementara tidak tersedia']], 503);
        }
    }

    public function legacyReports(): void
    {
        $db = $this->db(); if (!$db) return;
        $limit = min(1000, max(1, (int) ($_GET['limit'] ?? 50))); $offset = max(0, (int) ($_GET['offset'] ?? 0));
        $mechanicField = (string) ($_GET['mechanicField'] ?? 'name');
        $mechanicSearch = trim((string) ($_GET['mechanicSearch'] ?? ''));
        $foremanInput = trim((string) ($_GET['foremanId'] ?? ''));
        $from = trim((string) ($_GET['from'] ?? '')); $to = trim((string) ($_GET['to'] ?? ''));
        $where = ['d.job_site_id IS NULL']; $params = [];
        if (!in_array($mechanicField, ['name', 'nrpp'], true)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Jenis pencarian mekanik tidak valid']], 422); return; }
        if ($mechanicSearch !== '') {
            $column = $mechanicField === 'nrpp' ? 'c.nrpp' : 'c.nama';
            $where[] = "{$column} LIKE :mechanicSearch";
            $params['mechanicSearch'] = '%' . $mechanicSearch . '%';
        }
        if ($foremanInput !== '') {
            if (!ctype_digit($foremanInput) || (int) $foremanInput < 1) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Foreman tidak valid']], 422); return; }
            $where[] = 'd._id_mtc_fm = :foremanId AND fm.level_access = 0';
            $params['foremanId'] = (int) $foremanInput;
        }
        if ($from !== '') { if (!$this->validDate($from)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Tanggal awal tidak valid']], 422); return; } $where[] = 'd.tgl >= :fromDate'; $params['fromDate'] = $from; }
        if ($to !== '') { if (!$this->validDate($to)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Tanggal akhir tidak valid']], 422); return; } $where[] = 'd.tgl <= :toDate'; $params['toDate'] = $to; }
        $clause = implode(' AND ', $where);
        try {
            $count = $db->prepare("SELECT COUNT(*) FROM tb_dmar d LEFT JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm WHERE {$clause}"); $count->execute($params);
            $query = $db->prepare("SELECT d.id_dmar AS id, d._id_mtc_crew AS mechanicId, d._id_mtc_fm AS foremanId, d.tgl AS date, d.unit_code AS unitCode, d.model, d.hm, d.problem, d.activity, d.act_start AS `start`, d.act_end AS `finish`, d.code_job AS codeJob, d.status_unit AS unitStatus, d.component, d.remark, d.status_dmar AS status, d.created_at AS createdAt, c.nrpp AS mechanicNrpp, c.nama AS mechanicName, fm.nama AS foremanName FROM tb_dmar d LEFT JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm WHERE {$clause} ORDER BY d.tgl DESC, d.created_at DESC LIMIT {$limit} OFFSET {$offset}");
            $query->execute($params);
            Response::json(['ok' => true, 'data' => ['items' => $query->fetchAll(), 'total' => (int) $count->fetchColumn(), 'limit' => $limit, 'offset' => $offset]]);
        } catch (Throwable $error) {
            error_log('DMAR legacy reports list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Arsip laporan lama sementara tidak tersedia']], 503);
        }
    }

    public function legacyForemen(): void
    {
        $db = $this->db(); if (!$db) return;
        try {
            $query = $db->query('SELECT _id_mtc_fm AS id, nama AS name FROM tb_users_mtc_fm WHERE level_access = 0 ORDER BY nama');
            Response::json(['ok' => true, 'data' => ['items' => $query->fetchAll()]]);
        } catch (Throwable $error) {
            error_log('DMAR legacy foremen list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar foreman arsip sementara tidak tersedia']], 503);
        }
    }

    public function exportLegacyReports(): void
    {
        if (!$this->csrf()) return;
        $db = $this->db(); if (!$db) return;
        $input = $this->input(); if (!$input) return;
        $format = strtolower(trim((string) ($input['format'] ?? 'csv')));
        if (!in_array($format, ['csv', 'xlsx'], true)) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Format ekspor tidak valid']], 422); return;
        }
        $rawIds = $input['ids'] ?? null;
        if (!is_array($rawIds) || count($rawIds) < 1 || count($rawIds) > 5000) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Pilih antara 1 hingga 5000 laporan untuk diekspor']], 422); return;
        }
        $ids = [];
        foreach ($rawIds as $value) {
            if (filter_var($value, FILTER_VALIDATE_INT) === false || (int) $value < 1) {
                Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Daftar laporan yang dipilih tidak valid']], 422); return;
            }
            $ids[] = (int) $value;
        }
        $ids = array_values(array_unique($ids));
        $placeholders = [];
        $params = [];
        foreach ($ids as $index => $id) {
            $key = 'id' . $index;
            $placeholders[] = ':' . $key;
            $params[$key] = $id;
        }
        try {
            $query = $db->prepare("SELECT CASE WHEN d.job_site_id IS NULL THEN 'Tanpa Job Site' ELSE COALESCE(js.name, CONCAT('Site #', d.job_site_id)) END AS job_site, d.tgl, d.unit_code, d.model, d.hm, d.problem, d.activity, d.act_start, d.act_end, d.code_job, d.component, d.remark, CASE d.status_unit WHEN 0 THEN '-' WHEN 1 THEN 'Continue' WHEN 2 THEN 'RFU' ELSE 'Tidak diketahui' END AS status_unit, CASE d.status_dmar WHEN 1 THEN 'Approved' ELSE 'Pending' END AS status_dmar FROM tb_dmar d LEFT JOIN tb_job_sites js ON js.id = d.job_site_id WHERE d.job_site_id IS NULL AND d.id_dmar IN (" . implode(',', $placeholders) . ') ORDER BY d.tgl DESC, d.created_at DESC');
            $query->execute($params);
            $rows = $query->fetchAll();
            if (count($rows) !== count($ids)) { Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Sebagian laporan tidak ditemukan pada arsip lama']], 422); return; }
            if ($format === 'xlsx') {
                Response::json(['ok' => true, 'data' => ['items' => $rows]]);
                return;
            }
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="dmar-legacy-' . gmdate('Y-m-d') . '.csv"');
            header('Cache-Control: no-store');
            $output = fopen('php://output', 'wb');
            if ($output === false) throw new \RuntimeException('CSV stream could not be opened');
            fwrite($output, "\xEF\xBB\xBF");
            fputcsv($output, ['job_site', 'tgl', 'unit_code', 'model', 'hm', 'problem', 'activity', 'act_start', 'act_end', 'code_job', 'component', 'remark', 'status_unit', 'status_dmar'], ',', '"', '', "\r\n");
            foreach ($rows as $row) {
                $values = array_values($row);
                foreach ($values as $key => $value) {
                    if (is_string($value) && preg_match('/^[\s]*[=+@-]/u', $value)) $values[$key] = "'" . $value;
                }
                fputcsv($output, $values, ',', '"', '', "\r\n");
            }
            fclose($output);
        } catch (Throwable $error) {
            error_log('DMAR legacy reports export failed: ' . $error->getMessage());
            if (!headers_sent()) Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Ekspor CSV arsip gagal']], 503);
        }
    }

    private function validDate(string $date): bool
    {
        return preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) === 1 && checkdate((int) substr($date, 5, 2), (int) substr($date, 8, 2), (int) substr($date, 0, 4));
    }
}
