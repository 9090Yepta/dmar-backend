<?php
declare(strict_types=1);

use Dmar\Http\Response;
use Dmar\Http\Router;
use Dmar\Controllers\AuthController;
use Dmar\Controllers\ReportsController;
use Dmar\Controllers\AdminController;
use Dmar\Controllers\ProfileController;
use Dmar\Http\ImageUploadMiddleware;

require dirname(__DIR__) . '/src/bootstrap.php';

$router = new Router();
$router->get('/api/v1/health', static function (): void {
    Response::json([
        'ok' => true,
        'service' => 'dmar-api',
        'version' => 'v1',
    ]);
});
$router->post('/api/v1/auth/login', static function (): void {
    (new AuthController())->login();
});
$router->get('/api/v1/auth/me', static function (): void {
    (new AuthController())->me();
});
$router->post('/api/v1/auth/logout', static function (): void {
    (new AuthController())->logout();
});
$router->post('/api/v1/auth/password-change', static function (): void {
    (new AuthController())->changeMechanicPassword();
});
$router->post('/api/v1/account/profile-image', static function (): void {
    (new ProfileController())->uploadMechanicImage();
});
$router->get('/api/v1/media/{bucket}/{filename}', static function (string $bucket, string $filename): void {
    ImageUploadMiddleware::serve($bucket, $filename);
});
$router->get('/api/v1/catalogs/mechanic-report', static function (): void {
    (new ReportsController())->catalogs();
});
$router->get('/api/v1/catalogs/mechanic-units', static function (): void {
    (new ReportsController())->mechanicUnitOptions();
});
$router->get('/api/v1/reports/pending', static function (): void {
    (new ReportsController())->pending();
});
$router->get('/api/v1/reports/approved', static function (): void {
    (new ReportsController())->foremanApproved();
});
$router->get('/api/v1/reports/summary', static function (): void {
    (new ReportsController())->summary();
});
$router->get('/api/v1/reports', static function (): void {
    (new ReportsController())->index();
});
$router->post('/api/v1/reports', static function (): void {
    (new ReportsController())->create();
});
$router->get('/api/v1/reports/{id}', static function (string $id): void {
    (new ReportsController())->show($id);
});
$router->patch('/api/v1/reports/{id}', static function (string $id): void {
    (new ReportsController())->update($id);
});
$router->delete('/api/v1/reports/{id}', static function (string $id): void {
    (new ReportsController())->delete($id);
});
$router->post('/api/v1/reports/{id}/approve', static function (string $id): void {
    (new ReportsController())->approve($id);
});
$router->get('/api/v1/admin/users', static function (): void {
    (new AdminController())->users();
});
$router->get('/api/v1/admin/job-sites', static function (): void {
    (new AdminController())->jobSites();
});
$router->post('/api/v1/admin/job-sites', static function (): void {
    (new AdminController())->createJobSite();
});
$router->patch('/api/v1/admin/job-sites/{id}', static function (string $id): void {
    (new AdminController())->updateJobSite($id);
});
$router->post('/api/v1/admin/users', static function (): void {
    (new AdminController())->createUser();
});
$router->post('/api/v1/admin/users/{role}/{id}/password-reset', static function (string $role, string $id): void {
    (new AdminController())->resetPassword($role, $id);
});
$router->patch('/api/v1/admin/users/{role}/{id}', static function (string $role, string $id): void {
    (new AdminController())->updateUser($role, $id);
});
$router->post('/api/v1/admin/users/{role}/{id}', static function (string $role, string $id): void {
    (new AdminController())->updateUser($role, $id);
});
$router->delete('/api/v1/admin/users/{role}/{id}', static function (string $role, string $id): void {
    (new AdminController())->deleteUser($role, $id);
});
$router->get('/api/v1/admin/masters/{resource}', static function (string $resource): void {
    (new AdminController())->masters($resource);
});
$router->post('/api/v1/admin/masters/{resource}', static function (string $resource): void {
    (new AdminController())->createMaster($resource);
});
$router->patch('/api/v1/admin/masters/{resource}/{id}', static function (string $resource, string $id): void {
    (new AdminController())->updateMaster($resource, $id);
});
$router->post('/api/v1/admin/masters/{resource}/{id}', static function (string $resource, string $id): void {
    (new AdminController())->updateMaster($resource, $id);
});
$router->delete('/api/v1/admin/masters/{resource}/{id}', static function (string $resource, string $id): void {
    (new AdminController())->deleteMaster($resource, $id);
});
$router->get('/api/v1/admin/reports/approved/unit-options', static function (): void {
    (new AdminController())->approvedUnitOptions();
});
$router->get('/api/v1/admin/reports/approved', static function (): void {
    (new AdminController())->approvedReports();
});
$router->get('/api/v1/admin/dashboard', static function (): void {
    (new AdminController())->dashboard();
});
$router->get('/api/v1/admin/reports/legacy', static function (): void {
    (new AdminController())->legacyReports();
});
$router->get('/api/v1/admin/reports/legacy/foremen', static function (): void {
    (new AdminController())->legacyForemen();
});
$router->post('/api/v1/admin/reports/legacy/export', static function (): void {
    (new AdminController())->exportLegacyReports();
});

$router->dispatch(
    $_SERVER['REQUEST_METHOD'] ?? 'GET',
    parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/'
);
