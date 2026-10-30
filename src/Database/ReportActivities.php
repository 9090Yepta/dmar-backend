<?php
declare(strict_types=1);

namespace Dmar\Database;

use PDO;

final class ReportActivities
{
    /** @param list<array<string, mixed>> $reports
     *  @return list<array<string, mixed>>
     */
    public static function attach(PDO $db, array $reports): array
    {
        if ($reports === []) return $reports;

        $ids = array_values(array_unique(array_map(static fn (array $report): int => (int) $report['id'], $reports)));
        $parameters = [];
        $placeholders = [];
        foreach ($ids as $index => $id) {
            $key = 'report' . $index;
            $placeholders[] = ':' . $key;
            $parameters[$key] = $id;
        }

        $query = $db->prepare(
            'SELECT id_dmar_report AS reportId, activity_text AS activityText FROM tb_dmar_activities WHERE id_dmar_report IN (' . implode(', ', $placeholders) . ') ORDER BY id_dmar_report, activity_order'
        );
        $query->execute($parameters);
        $activitiesByReport = [];
        foreach ($query->fetchAll() as $activity) {
            $activitiesByReport[(int) $activity['reportId']][] = (string) $activity['activityText'];
        }

        foreach ($reports as &$report) {
            $id = (int) $report['id'];
            $activities = $activitiesByReport[$id] ?? [];
            $report['activities'] = $activities;
            $report['activity'] = implode("\n", $activities);
        }
        unset($report);

        return $reports;
    }

    /** @param list<string> $activities */
    public static function replace(PDO $db, int $reportId, array $activities): void
    {
        $delete = $db->prepare('DELETE FROM tb_dmar_activities WHERE id_dmar_report = :id');
        $delete->execute(['id' => $reportId]);

        $insert = $db->prepare('INSERT INTO tb_dmar_activities (id_dmar_report, activity_order, activity_text) VALUES (:id, :activityOrder, :activityText)');
        foreach ($activities as $index => $activity) {
            $insert->execute([
                'id' => $reportId,
                'activityOrder' => $index + 1,
                'activityText' => $activity,
            ]);
        }
    }
}
