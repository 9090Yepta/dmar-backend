<?php
declare(strict_types=1);

namespace Dmar\Http;

use PDO;

final class ReportSubmissionMiddleware
{
    /** @return array<string, mixed>|null */
    public function handle(array $input, PDO $db, int $siteId): ?array
    {
        $requiredFields = [
            'foremanId' => 'Foreman penanggung jawab',
            'date' => 'Tanggal laporan',
            'start' => 'Waktu mulai',
            'finish' => 'Waktu selesai',
            'codeJob' => 'Kode pekerjaan',
            'component' => 'Component group',
        ];
        foreach ($requiredFields as $key => $label) {
            if (!isset($input[$key]) || !is_scalar($input[$key]) || trim((string) $input[$key]) === '') {
                Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => $label . ' wajib diisi.']], 422);
                return null;
            }
        }

        $foremanId = (int) $input['foremanId'];
        $date = (string) $input['date'];
        if (array_key_exists('unitCode', $input) && !is_scalar($input['unitCode'])) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kode unit tidak valid']], 422);
            return null;
        }
        $unit = isset($input['unitCode']) ? trim((string) $input['unitCode']) : '';
        $rawActivities = $input['activities'] ?? (isset($input['activity']) ? [$input['activity']] : null);
        if (!is_array($rawActivities) || count($rawActivities) > 30) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Aktivitas harus berupa daftar dengan maksimal 30 item']], 422);
            return null;
        }

        $activities = [];
        foreach ($rawActivities as $rawActivity) {
            if (!is_string($rawActivity)) {
                Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Setiap aktivitas harus berupa teks']], 422);
                return null;
            }
            $activity = trim($rawActivity);
            if ($activity === '') continue;
            $activityLength = preg_match_all('/./us', $activity);
            if ($activityLength === false || $activityLength > 250) {
                Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Setiap aktivitas maksimal 250 karakter.']], 422);
                return null;
            }
            $activities[] = $activity;
        }
        if ($activities === []) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Minimal satu aktivitas wajib diisi']], 422);
            return null;
        }

        $start = (string) $input['start'];
        $finish = (string) $input['finish'];
        $shift = strtolower(trim((string) ($input['shift'] ?? 'day')));
        $status = filter_var($input['unitStatus'] ?? 0, FILTER_VALIDATE_INT);
        $problem = $input['problem'] ?? '';
        $remark = $input['remark'] ?? '';
        if (!is_string($problem) || !is_string($remark)) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Problem dan remark harus berupa teks']], 422);
            return null;
        }
        $problemLength = preg_match_all('/./us', $problem);
        $remarkLength = preg_match_all('/./us', $remark);
        $validDate = preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) === 1
            && checkdate((int) substr($date, 5, 2), (int) substr($date, 8, 2), (int) substr($date, 0, 4));
        $validTime = static function (string $time): bool {
            if (preg_match('/^(\d{2}):(\d{2})(?::(\d{2}))?$/', $time, $parts) !== 1) return false;
            return (int) $parts[1] <= 23 && (int) $parts[2] <= 59 && (int) ($parts[3] ?? 0) <= 59;
        };

        if (
            $foremanId < 1
            || !$validDate
            || !$validTime($start)
            || !$validTime($finish)
            || !in_array($shift, ['day', 'night'], true)
            || !in_array($status, [0, 1, 2], true)
            || strlen($unit) > 12
            || $problemLength === false || $problemLength > 350
            || $remarkLength === false || $remarkLength > 5000
        ) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Format tanggal, waktu, status unit, atau panjang salah satu isian tidak valid. Periksa kembali data laporan.']], 422);
            return null;
        }

        $toShiftMinutes = static function (string $time) use ($shift): int {
            $clockMinutes = ((int) substr($time, 0, 2) * 60) + (int) substr($time, 3, 2);
            if ($shift === 'day') return $clockMinutes;
            return $clockMinutes >= 1080 ? $clockMinutes - 1080 : $clockMinutes + 360;
        };
        $shiftStart = $shift === 'day' ? 360 : 0;
        $shiftEnd = $shift === 'day' ? 1080 : 720;
        $startMinutes = $toShiftMinutes($start);
        $finishMinutes = $toShiftMinutes($finish);
        $validShiftTimes = $startMinutes >= $shiftStart
            && $startMinutes < $shiftEnd
            && $finishMinutes > $startMinutes
            && $finishMinutes <= $shiftEnd;
        if (!$validShiftTimes) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Waktu selesai harus setelah waktu mulai dan tetap dalam batas shift']], 422);
            return null;
        }

        $foreman = $db->prepare('SELECT 1 FROM tb_users_mtc_fm f INNER JOIN tb_users_mtc_fm_job_sites fjs ON fjs._id_mtc_fm = f._id_mtc_fm WHERE f._id_mtc_fm = :id AND f.level_access = 0 AND f.status_data = 1 AND fjs.job_site_id = :site');
        $foreman->execute(['id' => $foremanId, 'site' => $siteId]);

        $model = null;
        if ($unit !== '') {
            $unitQuery = $db->prepare('SELECT model FROM tb_master_unit WHERE unit_code = :unit AND status_data = 1 LIMIT 1');
            $unitQuery->execute(['unit' => $unit]);
            $model = $unitQuery->fetchColumn();
            if ($model === false) {
                Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kode unit tidak ditemukan pada data master']], 422);
                return null;
            }
        }

        if (!$foreman->fetchColumn()) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Foreman tidak valid atau tidak bertugas di job site Anda. Silakan pilih foreman yang tersedia.']], 422);
            return null;
        }

        $code = $db->prepare('SELECT 1 FROM tb_master_codejob WHERE description = :value AND group_code IN (1, 2)');
        $code->execute(['value' => (string) $input['codeJob']]);
        if (!$code->fetchColumn()) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Kode pekerjaan yang dipilih tidak ditemukan atau sudah tidak berlaku. Silakan pilih ulang.']], 422);
            return null;
        }

        $component = $db->prepare('SELECT 1 FROM tb_master_component WHERE description = :value');
        $component->execute(['value' => (string) $input['component']]);
        if (!$component->fetchColumn()) {
            Response::json(['ok' => false, 'error' => ['code' => 'validation_error', 'message' => 'Component group yang dipilih tidak ditemukan atau sudah tidak berlaku. Silakan pilih ulang.']], 422);
            return null;
        }

        return [
            'foreman' => $foremanId,
            'date' => $date,
            'unit' => $unit !== '' ? $unit : null,
            'model' => $model,
            'hm' => trim((string) ($input['hm'] ?? '')),
            'problem' => trim($problem),
            'activities' => $activities,
            'start' => strlen($start) === 5 ? $start . ':00' : $start,
            'finish' => strlen($finish) === 5 ? $finish . ':00' : $finish,
            'code' => (string) $input['codeJob'],
            'component' => (string) $input['component'],
            'remark' => trim($remark),
            'unitStatus' => $status,
        ];
    }
}
