<?php
declare(strict_types=1);

namespace Dmar\Controllers;

use Dmar\Database\Connection;
use Dmar\Database\ReportActivities;
use Dmar\Http\Request;
use Dmar\Http\Response;
use Dmar\Http\ImageUploadMiddleware;
use JsonException;
use PDO;
use Throwable;

final class ReportsController
{
    private function user(): ?array
    {
        return isset($_SESSION['dmar_user']) && is_array($_SESSION['dmar_user']) ? $_SESSION['dmar_user'] : null;
    }

    private function requireCsrf(): bool
    {
        $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $known = $_SESSION['dmar_csrf'] ?? '';
        if (is_string($sent) && is_string($known) && $known !== '' && hash_equals($known, $sent)) {
            return true;
        }
        Response::json(['ok' => false, 'error' => ['code' => 'csrf_failed', 'message' => 'Token keamanan tidak valid']], 403);
        return false;
    }

    private function db(): ?PDO
    {
        $portalContext = $_SERVER['HTTP_X_DMAR_PORTAL'] ?? '';
        if ($this->user() === null || ($this->user()['portal'] ?? null) !== $portalContext) {
            Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk terlebih dahulu']], 401);
            return null;
        }
        try {
            if (!in_array($portalContext, ['mekanik', 'staff'], true)) {
                Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Silakan masuk terlebih dahulu']], 401);
                return null;
            }
            $isMechanic = $portalContext === 'mekanik';
            $table = $isMechanic ? 'tb_users_mtc_crew' : 'tb_users_mtc_fm';
            $idColumn = $isMechanic ? '_id_mtc_crew' : '_id_mtc_fm';
            $db = Connection::create();
            $assignmentSelect = $isMechanic
                ? 'NULL AS assignedJobSiteNames'
                : "(SELECT GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ' · ') FROM tb_users_mtc_fm_job_sites fjs JOIN tb_job_sites s ON s.id = fjs.job_site_id WHERE fjs._id_mtc_fm = u._id_mtc_fm) AS assignedJobSiteNames";
            $query = $db->prepare("SELECT u.{$idColumn} AS id, u.nrpp, u.nama, u.jabatan, u.level_access, u.job_site_id AS jobSiteId, js.name AS jobSiteName, {$assignmentSelect} FROM {$table} u LEFT JOIN tb_job_sites js ON js.id = u.job_site_id WHERE u.{$idColumn} = :id AND u.status_data = 1 LIMIT 1");
            $query->execute(['id' => (int) $this->user()['id']]);
            $account = $query->fetch();
            if (!$account) {
                Response::json(['ok' => false, 'error' => ['code' => 'unauthenticated', 'message' => 'Akun tidak ditemukan']], 401);
                return null;
            }
            $level = (int) $account['level_access'];
            if (!$isMechanic && !in_array($level, [0, 1, 2], true)) {
                Response::json(['ok' => false, 'error' => ['code' => 'invalid_role', 'message' => 'Level akses akun tidak valid']], 403);
                return null;
            }
            $_SESSION['dmar_user'] = [
                'id' => (int) $account['id'],
                'nrpp' => (string) $account['nrpp'],
                'name' => (string) $account['nama'],
                'position' => (string) ($account['jabatan'] ?? ''),
                'portal' => $portalContext,
                'role' => $isMechanic ? 'mechanic' : match ($level) { 0 => 'foreman', 1 => 'admin', 2 => 'superadmin' },
                'jobSiteId' => isset($account['jobSiteId']) ? (int) $account['jobSiteId'] : null,
                'jobSiteName' => !$isMechanic && $level === 0
                    ? (string) ($account['assignedJobSiteNames'] ?? '') ?: null
                    : (isset($account['jobSiteName']) ? (string) $account['jobSiteName'] : null),
            ];
            return $db;
        } catch (Throwable $error) {
            error_log('DMAR report query failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Layanan data sementara tidak tersedia ya']], 503);
            return null;
        }
    }

    private function mechanic(): bool
    {
        if (($this->user()['role'] ?? '') === 'mechanic') return true;
        Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Akses ini hanya tersedia untuk mekanik']], 403);
        return false;
    }

    private function staff(): bool
    {
        if (in_array($this->user()['role'] ?? '', ['foreman', 'admin', 'superadmin'], true)) return true;
        Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Akses ini hanya tersedia untuk staff']], 403);
        return false;
    }

    public function catalogs(): void
    {
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        $siteId = (int) ($this->user()['jobSiteId'] ?? 0);
        if ($siteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Akun Anda belum ditempatkan pada job site. Hubungi admin.']], 403); return; }
        try {
            $foremanQuery = $db->prepare("SELECT f._id_mtc_fm AS id, f.nama AS name, f.profile_image_path AS profileImagePath FROM tb_users_mtc_fm f INNER JOIN tb_users_mtc_fm_job_sites fjs ON fjs._id_mtc_fm = f._id_mtc_fm WHERE f.level_access = 0 AND f.status_data = 1 AND fjs.job_site_id = :site ORDER BY f.nama");
            $foremanQuery->execute(['site' => $siteId]);
            $foremen = $foremanQuery->fetchAll();
            foreach ($foremen as &$foreman) {
                $foreman['profileImageUrl'] = ImageUploadMiddleware::url($foreman['profileImagePath'] ?? null);
                unset($foreman['profileImagePath']);
            }
            unset($foreman);
            $codes = $db->query("SELECT description, group_code AS groupCode FROM tb_master_codejob WHERE group_code IN (1, 2) ORDER BY group_code, sorted, description")->fetchAll();
            $components = $db->query("SELECT description FROM tb_master_component ORDER BY sorted, description")->fetchAll(PDO::FETCH_COLUMN);
            $query = $db->prepare('SELECT unit_code AS unitCode, model, brand, image_path AS imagePath FROM tb_master_unit WHERE status_data = 1 AND unit_code LIKE :term ORDER BY unit_code LIMIT 20');
            $query->execute(['term' => (string) ($_GET['unit'] ?? '') . '%']);
            $units = $query->fetchAll();
            foreach ($units as &$unit) {
                $unit['imageUrl'] = ImageUploadMiddleware::url($unit['imagePath'] ?? null);
                unset($unit['imagePath']);
            }
            unset($unit);
            Response::json(['ok' => true, 'data' => ['foremen' => $foremen, 'jobCodes' => $codes, 'components' => $components, 'units' => $units]]);
        } catch (Throwable $error) {
            error_log('DMAR catalogs query failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Data referensi sementara tidak tersedia']], 503);
        }
    }

    public function mechanicUnitOptions(): void
    {
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        $term = strtoupper(trim((string) ($_GET['query'] ?? '')));
        if ($term === '') {
            Response::json(['ok' => true, 'data' => ['units' => []]]);
            return;
        }
        try {
            $query = $db->prepare('SELECT unit_code AS unitCode, model, brand, image_path AS imagePath FROM tb_master_unit WHERE status_data = 1 AND (unit_code LIKE :code OR model LIKE :model) ORDER BY unit_code LIMIT 20');
            $query->execute(['code' => $term . '%', 'model' => $term . '%']);
            $units = $query->fetchAll();
            foreach ($units as &$unit) {
                $unit['imageUrl'] = ImageUploadMiddleware::url($unit['imagePath'] ?? null);
                unset($unit['imagePath']);
            }
            unset($unit);
            Response::json(['ok' => true, 'data' => ['units' => $units]]);
        } catch (Throwable $error) {
            error_log('DMAR unit search failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Pencarian unit sementara tidak tersedia']], 503);
        }
    }

    public function index(): void
    {
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        $user = $this->user();
        $limit = min(100, max(1, (int) ($_GET['limit'] ?? 25)));
        $offset = max(0, (int) ($_GET['offset'] ?? 0));
        $search = trim(substr((string) ($_GET['search'] ?? ''), 0, 100));
        $searchBy = ($_GET['searchBy'] ?? 'unit') === 'activity' ? 'activity' : 'unit';
        $where = 'd._id_mtc_crew = :crew';
        $params = ['crew' => (int) $user['id']];
        if ($search !== '') {
            if ($searchBy === 'activity') {
                $where .= ' AND EXISTS (SELECT 1 FROM tb_dmar_activities da WHERE da.id_dmar_report = d.id_dmar_report AND da.activity_text LIKE :search)';
                $params['search'] = '%' . $search . '%';
            } else {
                $where .= ' AND (d.unit_code LIKE :unitCode OR d.model LIKE :model)';
                $params['unitCode'] = '%' . $search . '%';
                $params['model'] = '%' . $search . '%';
            }
        }
        $foremanId = (int) ($_GET['foremanId'] ?? 0);
        if ($foremanId > 0) {
            $where .= ' AND d._id_mtc_fm = :foreman';
            $params['foreman'] = $foremanId;
        }
        $status = (string) ($_GET['status'] ?? '');
        if ($status === 'pending') {
            $where .= ' AND d.status_dmar = 0';
        } elseif ($status === 'approved') {
            $where .= ' AND d.status_dmar = 1';
        }
        try {
            $count = $db->prepare("SELECT COUNT(*) FROM tb_dmar_v2 d WHERE {$where}");
            $count->execute($params);
            $query = $db->prepare("SELECT d.id_dmar_report AS id, d._id_mtc_fm AS foremanId, fm.nama AS foremanName, d.tgl AS date, d.unit_code AS unitCode, d.model, d.hm, d.problem, d.act_start AS `start`, d.act_end AS `finish`, d.code_job AS codeJob, d.status_unit AS unitStatus, d.component, d.remark, d.status_dmar AS approved, d.created_at AS createdAt FROM tb_dmar_v2 d LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm WHERE {$where} ORDER BY d.created_at DESC LIMIT {$limit} OFFSET {$offset}");
            $query->execute($params);
            $items = ReportActivities::attach($db, $query->fetchAll());
            $foremenQuery = $db->prepare('SELECT DISTINCT fm._id_mtc_fm AS id, fm.nama AS name FROM tb_dmar_v2 d INNER JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm WHERE d._id_mtc_crew = :crew ORDER BY fm.nama');
            $foremenQuery->execute(['crew' => (int) $user['id']]);
            Response::json(['ok' => true, 'data' => ['items' => $items, 'total' => (int) $count->fetchColumn(), 'foremen' => $foremenQuery->fetchAll(), 'limit' => $limit, 'offset' => $offset]]);
        } catch (Throwable $error) {
            error_log('DMAR reports list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar laporan sementara tidak tersedia']], 503);
        }
    }

    public function summary(): void
    {
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        $crewId = (int) $this->user()['id'];
        $monthStart = new \DateTimeImmutable('first day of this month');
        $nextMonth = $monthStart->modify('+1 month');
        try {
            $totalsQuery = $db->prepare('SELECT COUNT(*) AS total, COALESCE(SUM(status_dmar = 0), 0) AS pending, COALESCE(SUM(status_dmar = 1), 0) AS approved FROM tb_dmar_v2 WHERE _id_mtc_crew = :crew');
            $totalsQuery->execute(['crew' => $crewId]);
            $totals = $totalsQuery->fetch() ?: [];

            $daysQuery = $db->prepare('SELECT DATE(tgl) AS `date`, COUNT(*) AS total, COALESCE(SUM(status_dmar = 0), 0) AS pending, COALESCE(SUM(status_dmar = 1), 0) AS approved FROM tb_dmar_v2 WHERE _id_mtc_crew = :crew AND tgl >= :monthStart AND tgl < :nextMonth GROUP BY DATE(tgl) ORDER BY `date`');
            $daysQuery->execute([
                'crew' => $crewId,
                'monthStart' => $monthStart->format('Y-m-d'),
                'nextMonth' => $nextMonth->format('Y-m-d'),
            ]);
            $days = array_map(static fn (array $row): array => [
                'date' => (string) $row['date'],
                'total' => (int) $row['total'],
                'pending' => (int) $row['pending'],
                'approved' => (int) $row['approved'],
            ], $daysQuery->fetchAll());

            Response::json(['ok' => true, 'data' => [
                'total' => (int) ($totals['total'] ?? 0),
                'pending' => (int) ($totals['pending'] ?? 0),
                'approved' => (int) ($totals['approved'] ?? 0),
                'days' => $days,
            ]]);
        } catch (Throwable $error) {
            error_log('DMAR mechanic report summary failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Ringkasan laporan sementara tidak tersedia']], 503);
        }
    }

    public function pending(): void
    {
        $db = $this->db();
        if (!$db || !$this->staff()) return;
        $user = $this->user();
        $where = 'd.status_dmar = 0';
        $params = [];
        if ($user['role'] === 'foreman') {
            $where .= ' AND d._id_mtc_fm = :foreman';
            $params['foreman'] = (int) $user['id'];
            $where .= ' AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = d._id_mtc_fm AND fjs.job_site_id = d.job_site_id)';
        } elseif ($user['role'] === 'admin') {
            $siteId = (int) ($user['jobSiteId'] ?? 0);
            if ($siteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Akun admin belum ditempatkan pada job site.']], 403); return; }
            $where .= ' AND d.job_site_id = :site';
            $params['site'] = $siteId;
        }
        try {
            $query = $db->prepare("SELECT d.id_dmar_report AS id, d._id_mtc_fm AS foremanId, d.job_site_id AS jobSiteId, js.name AS jobSiteName, d.tgl AS date, d.unit_code AS unitCode, d.model, d.hm, d.problem, d.act_start AS `start`, d.act_end AS `finish`, d.code_job AS codeJob, d.status_unit AS unitStatus, d.component, d.remark, c.nrpp AS mechanicNrpp, c.nama AS mechanicName, c.profile_image_path AS mechanicProfileImagePath, fm.nama AS foremanName FROM tb_dmar_v2 d INNER JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew LEFT JOIN tb_users_mtc_fm fm ON fm._id_mtc_fm = d._id_mtc_fm LEFT JOIN tb_job_sites js ON js.id = d.job_site_id WHERE {$where} ORDER BY d.created_at DESC");
            $query->execute($params);
            $items = ReportActivities::attach($db, $query->fetchAll());
            foreach ($items as &$item) {
                $item['mechanicProfileImageUrl'] = ImageUploadMiddleware::url($item['mechanicProfileImagePath'] ?? null);
                unset($item['mechanicProfileImagePath']);
            }
            unset($item);
            Response::json(['ok' => true, 'data' => ['items' => $items]]);
        } catch (Throwable $error) {
            error_log('DMAR pending list failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Daftar persetujuan sementara tidak tersedia']], 503);
        }
    }

    public function foremanApproved(): void
    {
        $db = $this->db();
        if (!$db || !$this->staff()) return;
        $user = $this->user();
        if (($user['role'] ?? '') !== 'foreman') {
            Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Riwayat ini hanya tersedia untuk foreman']], 403);
            return;
        }
        $limit = min(100, max(1, (int) ($_GET['limit'] ?? 50)));
        $offset = max(0, (int) ($_GET['offset'] ?? 0));
        $searchBy = ($_GET['searchBy'] ?? 'name') === 'nrpp' ? 'nrpp' : 'name';
        $search = trim(substr((string) ($_GET['search'] ?? ''), 0, 100));
        $where = 'd.status_dmar = 1 AND d._id_mtc_fm = :foreman AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = d._id_mtc_fm AND fjs.job_site_id = d.job_site_id)';
        $params = ['foreman' => (int) $user['id']];
        if ($search !== '') {
            $where .= $searchBy === 'nrpp'
                ? ' AND c.nrpp LIKE :mechanicSearch'
                : ' AND c.nama LIKE :mechanicSearch';
            $params['mechanicSearch'] = '%' . $search . '%';
        }
        try {
            $count = $db->prepare("SELECT COUNT(*) FROM tb_dmar_v2 d INNER JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew WHERE {$where}");
            $count->execute($params);
            $query = $db->prepare("SELECT d.id_dmar_report AS id, c.nrpp AS mechanicNrpp, c.nama AS mechanicName, d.unit_code AS unitCode, d.model, d.tgl AS date, d.approved_at AS approvedAt FROM tb_dmar_v2 d INNER JOIN tb_users_mtc_crew c ON c._id_mtc_crew = d._id_mtc_crew WHERE {$where} ORDER BY d.approved_at DESC, d.tgl DESC, d.id_dmar_report DESC LIMIT {$limit} OFFSET {$offset}");
            $query->execute($params);
            Response::json(['ok' => true, 'data' => ['items' => $query->fetchAll(), 'total' => (int) $count->fetchColumn(), 'limit' => $limit, 'offset' => $offset]]);
        } catch (Throwable $error) {
            error_log('DMAR foreman approved history failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Riwayat laporan approved sementara tidak tersedia']], 503);
        }
    }

    public function create(): void
    {
        if (!$this->requireCsrf()) return;
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        try { $input = Request::json(); } catch (JsonException) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Body JSON tidak valid']], 400); return;
        }
        $siteId = (int) ($this->user()['jobSiteId'] ?? 0);
        if ($siteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Akun Anda belum ditempatkan pada job site. Hubungi admin.']], 403); return; }
        $values = (new \Dmar\Http\ReportSubmissionMiddleware())->handle($input, $db, $siteId);
        if ($values === null) return;
        $user = $this->user();
        try {
            $db->beginTransaction();
            $query = $db->prepare('INSERT INTO tb_dmar_v2 (_id_mtc_crew, _id_mtc_fm, job_site_id, tgl, unit_code, model, hm, problem, act_start, act_end, code_job, component, remark, status_unit, status_dmar) VALUES (:crew, :foreman, :site, :date, :unit, :model, :hm, :problem, :start, :finish, :code, :component, :remark, :unitStatus, 0)');
            $parentValues = $values;
            unset($parentValues['activities']);
            $query->execute($parentValues + ['crew' => (int) $user['id'], 'site' => $siteId]);
            $reportId = (int) $db->lastInsertId();
            ReportActivities::replace($db, $reportId, $values['activities']);
            $db->commit();
            Response::json(['ok' => true, 'data' => ['id' => $reportId]], 201);
        } catch (Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            error_log('DMAR report create failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Laporan gagal disimpan']], 503);
        }
    }

    public function show(string $id): void
    {
        $db = $this->db();
        if (!$db) return;
        $user = $this->user();
        if (!in_array($user['role'] ?? '', ['mechanic', 'foreman', 'admin', 'superadmin'], true)) { $this->staff(); return; }
        $where = 'd.id_dmar_report = :id';
        $params = ['id' => (int) $id];
        if ($user['role'] === 'mechanic') { $where .= ' AND d._id_mtc_crew = :uid'; $params['uid'] = (int) $user['id']; }
        if ($user['role'] === 'foreman') { $where .= ' AND d._id_mtc_fm = :uid AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = d._id_mtc_fm AND fjs.job_site_id = d.job_site_id)'; $params['uid'] = (int) $user['id']; }
        if ($user['role'] === 'admin') { $where .= ' AND d.job_site_id = :site'; $params['site'] = (int) ($user['jobSiteId'] ?? 0); }
        try {
            $query = $db->prepare("SELECT d.id_dmar_report AS id, d._id_mtc_fm AS foremanId, d.tgl AS date, d.unit_code AS unitCode, d.model, d.hm, d.problem, d.act_start AS `start`, d.act_end AS `finish`, d.code_job AS codeJob, d.status_unit AS unitStatus, d.component, d.remark, d.status_dmar AS approved FROM tb_dmar_v2 d WHERE {$where} LIMIT 1");
            $query->execute($params);
            $item = $query->fetch();
            if (!$item) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Laporan tidak ditemukan']], 404); return; }
            $item = ReportActivities::attach($db, [$item])[0];
            Response::json(['ok' => true, 'data' => ['item' => $item]]);
        } catch (Throwable $error) {
            error_log('DMAR report detail failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Detail laporan sementara tidak tersedia']], 503);
        }
    }

    public function update(string $id): void
    {
        if (!$this->requireCsrf()) return;
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        try { $input = Request::json(); } catch (JsonException) {
            Response::json(['ok' => false, 'error' => ['code' => 'invalid_json', 'message' => 'Body JSON tidak valid']], 400); return;
        }
        $existing = $db->prepare('SELECT job_site_id FROM tb_dmar_v2 WHERE id_dmar_report = :id AND _id_mtc_crew = :crew AND status_dmar = 0 LIMIT 1');
        $existing->execute(['id' => (int) $id, 'crew' => (int) $this->user()['id']]);
        $siteId = (int) ($existing->fetchColumn() ?: 0);
        if ($siteId < 1) { Response::json(['ok' => false, 'error' => ['code' => 'job_site_required', 'message' => 'Laporan ini tidak ditemukan atau belum memiliki job site.']], 409); return; }
        $values = (new \Dmar\Http\ReportSubmissionMiddleware())->handle($input, $db, $siteId);
        if ($values === null) return;
        $values['id'] = (int) $id;
        $values['crew'] = (int) $this->user()['id'];
        try {
            $db->beginTransaction();
            $query = $db->prepare('UPDATE tb_dmar_v2 SET _id_mtc_fm = :foreman, tgl = :date, unit_code = :unit, model = :model, hm = :hm, problem = :problem, act_start = :start, act_end = :finish, code_job = :code, component = :component, remark = :remark, status_unit = :unitStatus WHERE id_dmar_report = :id AND _id_mtc_crew = :crew AND status_dmar = 0');
            $parentValues = $values;
            unset($parentValues['activities']);
            $query->execute($parentValues);
            if ($query->rowCount() === 0 && !$this->ownsPending($db, (int) $id, (int) $values['crew'])) { $db->rollBack(); Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Laporan pending milik Anda tidak ditemukan']], 404); return; }
            ReportActivities::replace($db, (int) $id, $values['activities']);
            $db->commit();
            Response::json(['ok' => true, 'data' => ['updated' => true]]);
        } catch (Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            error_log('DMAR report update failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Laporan gagal diperbarui']], 503);
        }
    }

    private function ownsPending(PDO $db, int $id, int $crew): bool
    {
        $query = $db->prepare('SELECT 1 FROM tb_dmar_v2 WHERE id_dmar_report = :id AND _id_mtc_crew = :crew AND status_dmar = 0');
        $query->execute(['id' => $id, 'crew' => $crew]);
        return (bool) $query->fetchColumn();
    }

    public function delete(string $id): void
    {
        if (!$this->requireCsrf()) return;
        $db = $this->db();
        if (!$db || !$this->mechanic()) return;
        try {
            $query = $db->prepare('DELETE FROM tb_dmar_v2 WHERE id_dmar_report = :id AND _id_mtc_crew = :crew AND status_dmar = 0');
            $query->execute(['id' => (int) $id, 'crew' => (int) $this->user()['id']]);
            if ($query->rowCount() !== 1) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Laporan pending milik Anda tidak ditemukan']], 404); return; }
            Response::json(['ok' => true, 'data' => ['deleted' => true]]);
        } catch (Throwable $error) {
            error_log('DMAR report delete failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Laporan gagal dihapus']], 503);
        }
    }

    public function approve(string $id): void
    {
        if (!$this->requireCsrf()) return;
        $db = $this->db();
        if (!$db || !$this->staff()) return;
        $user = $this->user();
        if ($user['role'] === 'admin') {
            Response::json(['ok' => false, 'error' => ['code' => 'forbidden', 'message' => 'Admin hanya dapat melihat laporan pending, bukan menyetujuinya']], 403); return;
        }
        $where = 'id_dmar_report = :id AND status_dmar = 0';
        $params = ['id' => (int) $id];
        if ($user['role'] === 'foreman') { $where .= ' AND _id_mtc_fm = :foreman AND EXISTS (SELECT 1 FROM tb_users_mtc_fm_job_sites fjs WHERE fjs._id_mtc_fm = tb_dmar_v2._id_mtc_fm AND fjs.job_site_id = tb_dmar_v2.job_site_id)'; $params['foreman'] = (int) $user['id']; }
        if ($user['role'] === 'admin') { $where .= ' AND job_site_id = :site'; $params['site'] = (int) ($user['jobSiteId'] ?? 0); }
        try {
            $query = $db->prepare("UPDATE tb_dmar_v2 SET status_dmar = 1, approved_at = CURRENT_TIMESTAMP WHERE {$where}");
            $query->execute($params);
            if ($query->rowCount() !== 1) { Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Laporan pending yang ditugaskan tidak ditemukan']], 404); return; }
            Response::json(['ok' => true, 'data' => ['approved' => true]]);
        } catch (Throwable $error) {
            error_log('DMAR report approval failed: ' . $error->getMessage());
            Response::json(['ok' => false, 'error' => ['code' => 'service_unavailable', 'message' => 'Persetujuan gagal disimpan']], 503);
        }
    }

}
