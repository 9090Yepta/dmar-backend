<?php
declare(strict_types=1);

namespace Dmar\Http;

final class Router
{
    /** @var array<string, callable> */
    private array $routes = [];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET ' . $path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST ' . $path] = $handler;
    }

    public function patch(string $path, callable $handler): void
    {
        $this->routes['PATCH ' . $path] = $handler;
    }

    public function delete(string $path, callable $handler): void
    {
        $this->routes['DELETE ' . $path] = $handler;
    }

    public function dispatch(string $method, string $path): void
    {
        $normalizedMethod = strtoupper($method);
        if (!AuthMiddleware::isPublicRequest($normalizedMethod, $path) && !AuthMiddleware::requireValidSession()) {
            return;
        }

        $key = $normalizedMethod . ' ';
        foreach ($this->routes as $route => $handler) {
            if (!str_starts_with($route, $key)) {
                continue;
            }
            $pattern = preg_replace_callback('/\\{([a-zA-Z][a-zA-Z0-9_]*)\\}/', static fn (array $m): string => '(?P<' . $m[1] . '>[^/]+)', substr($route, strlen($key)));
            if (preg_match('#^' . $pattern . '$#', $path, $matches) !== 1) {
                continue;
            }
            $params = [];
            foreach ($matches as $name => $value) {
                if (is_string($name)) {
                    $params[$name] = rawurldecode($value);
                }
            }
            $handler(...array_values($params));
            return;
        }

        Response::json(['ok' => false, 'error' => ['code' => 'not_found', 'message' => 'Route not found']], 404);
    }
}
