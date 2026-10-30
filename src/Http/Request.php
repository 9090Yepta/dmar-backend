<?php
declare(strict_types=1);

namespace Dmar\Http;

use JsonException;

final class Request
{
    /** @return array<string, mixed> */
    public static function json(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') {
            throw new JsonException('Request body is empty');
        }

        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new JsonException('Expected a JSON object');
        }

        return $data;
    }
}
