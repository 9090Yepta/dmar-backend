<?php
declare(strict_types=1);

namespace Dmar\Database;

use PDO;
use RuntimeException;

final class Connection
{
    public static function create(): PDO
    {
        foreach (['DB_HOST', 'DB_NAME', 'DB_USERNAME'] as $required) {
            if (getenv($required) === false || getenv($required) === '') {
                throw new RuntimeException('Missing database setting: ' . $required);
            }
        }

        $host = getenv('DB_HOST');
        $port = getenv('DB_PORT') ?: '3306';
        $name = getenv('DB_NAME');
        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $host, $port, $name);

        return new PDO($dsn, (string) getenv('DB_USERNAME'), (string) (getenv('DB_PASSWORD') ?: ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
}
