<?php
declare(strict_types=1);

use App\Application\Actions\User\ListUsersAction;
use App\Application\Actions\User\ViewUserAction;
use App\Object\User;
use Slim\App;
use Slim\Interfaces\RouteCollectorProxyInterface as Group;

return function (App $app) {
    $app->post('/login', User::class . ':login');
    $app->post('/login/key', User::class . ':loginValidation');
    $app->post('/register', User::class . ':register');
    $app->post('/totp', User::class . ':totp');
    $app->post('/totp/validation', User::class . ':totpV');
    $app->post('/token/check', User::class . ':tokenValidation');
};
