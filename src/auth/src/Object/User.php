<?php


namespace App\Object;


use Otp\GoogleAuthenticator;
use Otp\Otp;
use ParagonIE\ConstantTime\Encoding;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class User
{
    public function login (Request $request, Response $response, $args) {
        $mail = filter_input(INPUT_POST, 'mail', FILTER_SANITIZE_EMAIL);
        $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

        if (isset($mail) && isset($password)) {
            if (filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                $query = "SELECT id, name, mail, password, totp_key FROM user WHERE mail = :mail";
                $db = new Database();
                $connection = $db->getConnection();
                $req = $connection->prepare($query);
                $req->bindParam(':mail', $mail);

                $req->execute();

                if ($req->rowCount() > 0) {
                    $data = $req->fetch();
                    $dbid = $data['id'];
                    $dbName = $data['name'];
                    $dbmail = $data['mail'];
                    $dbpassword = $data['password'];
                    if (password_verify($password, $dbpassword)) {
                        $tokenFactory = new Token();
                        $token = $tokenFactory->generateTemporaryToken($dbmail, $dbid);
                        $data = json_encode(array(
                            "id" => $dbid,
                            "name" => $dbName,
                            "mail" => $dbmail,
                            "token" => $token,
                            "double-check" => $data['totp_key'] !== null
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(200);
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => "400",
                        "message" => "wrong email or password"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(400);
            }
            $data = json_encode(array(
                "error" => [
                    "code" => "400",
                    "message" => "Bad email format"
                ]
            ));
            $response->getBody()->write($data);
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(400);
        }
        $data = json_encode(array(
            "error" => [
                "code" => "400",
                "message" => "some data are missing"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(400);
    }

    public function register (Request $request, Response $response, $args) {
        $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
        $mail = filter_input(INPUT_POST, 'mail', FILTER_SANITIZE_EMAIL);
        $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

        if (isset($name) && isset($mail) && isset($password)) {
            if (strlen($password) >= 8) {
                if (filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                    $query = "INSERT INTO `user`(`name`, `mail`, `password`, `created_at`, `update_at`) VALUES (:name, :mail, :password, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";

                    $db = new Database();

                    $connection = $db->getConnection();

                    $req = $connection->prepare($query);

                    $req->bindParam(':name', $name);
                    $req->bindParam(':mail', $mail);
                    $hash = password_hash($password, PASSWORD_DEFAULT);
                    $req->bindParam(':password', $hash);

                    try {
                        $req->execute();
                        $data = json_encode(array(
                            "name" => $name,
                            "mail" => $mail
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(201);
                    } catch (\PDOException $e) {
                        if (!strpos($e->getMessage(), 'SQLSTATE[23000]')) {
                            $data = json_encode(array(
                                "error" => [
                                    "code" => "409",
                                    "message" => "This email is already registered"
                                ]
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(409);
                        }
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => "400",
                        "message" => "Bad email format"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(400);
            }
            $data = json_encode(array(
                "error" => [
                    "code" => "400",
                    "message" => "Password to short, 8 character required"
                ]
            ));
            $response->getBody()->write($data);
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(400);
        }
        $data = json_encode(array(
            "error" => [
                "code" => "400",
                "message" => "some data are missing"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(400);
    }

    public function totp (Request $request, Response $response, $args)
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if ($bearer[0] == 'Bearer') {
                $tokenVerificator = new Token();
                $data = $tokenVerificator->validateToken($bearer[1]);
                if ($data) {
                    if (isset($data->mail) && isset($data->id)) {
                        $secret = GoogleAuthenticator::generateRandom();
                        $qrCode = GoogleAuthenticator::getQrCodeUrl('totp', "OAuth martitom for $data->mail", $secret);
                        // update de la base
                        $query = "UPDATE user SET totp_key = '$secret', totp_key_validate = false WHERE id = :id";
                        $db = new Database();
                        $connection = $db->getConnection();
                        $req = $connection->prepare($query);
                        $req->bindParam(':id', $data->id);

                        $req->execute();

                        $data = json_encode(array(
                            "id" => $data->id,
                            "mail" => $data->mail,
                            "token" => $bearer[1],
                            "qr_url" => $qrCode
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(200);
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => 400,
                        "message" => "invalid token"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(400);
            }
        }
        $data = json_encode(array(
            "error" => [
                "code" => 400,
                "message" => "some data are missing"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(400);
    }

    public function totpV (Request $request, Response $response, $args) {
        $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
        $key = $_POST['key'];
        if ($bearer[0] == 'Bearer') {
            $tokenVerificator = new Token();
            $data =  $tokenVerificator->validateToken($bearer[1]);
            if ($data) {
                if (isset($data->mail) && isset($data->id)) {
                    $query = "SELECT totp_key, name, totp_key_validate FROM user WHERE id = :id AND totp_key IS NOT null";
                    $db = new Database();
                    $connection = $db->getConnection();
                    $req = $connection->prepare($query);
                    $req->bindParam(':id', $data->id);
                    $req->execute();

                    if ($req->rowCount() > 0) {
                        $row = $req->fetch();
                        if ($row['totp_key_validate'] == 0) {
                            $secret = $row['totp_key']; // get the secret in the base

                            $otp = new Otp();
                            if ($otp->checkTotp(Encoding::base32DecodeUpper($secret), $key)) {
                                // validate the secret and resend a good token
                                $query = "UPDATE user SET totp_key_validate = true WHERE id = :id";
                                $db = new Database();
                                $connection = $db->getConnection();
                                $req = $connection->prepare($query);
                                $req->bindParam(':id', $data->id);
                                $req->execute();

                                $token = $tokenVerificator->generate($data->id, $data->mail, $row['name']);

                                $data = json_encode(array(
                                    "id" => $data->id,
                                    "mail" => $data->mail,
                                    "token" => $token,
                                ));
                                $response->getBody()->write($data);
                                return $response
                                    ->withHeader('Content-Type', 'application/json')
                                    ->withStatus(200);
                            }
                            // receive a alert message when the user have already validate the secret
                            $data = json_encode(array(
                                "error" => [
                                    "code" => 400,
                                    "message" => "wrong key"
                                ]
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(400);
                        }
                        $data = json_encode(array(
                            "error" => [
                                "code" => 400,
                                "message" => "data key already validate"
                            ]
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(400);
                    }
                    $data = json_encode(array(
                        "error" => [
                            "code" => 400,
                            "message" => "no key params"
                        ]
                    ));
                    $response->getBody()->write($data);
                    return $response
                        ->withHeader('Content-Type', 'application/json')
                        ->withStatus(400);
                }
            }
        }
    }

    // create a function dblAuthenticate key
    public function loginValidation (Request $request, Response $response, $args) {
        $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
        $key = $_POST['key'];
        if ($bearer[0] == 'Bearer') {
            $tokenVerificator = new Token();
            $data =  $tokenVerificator->validateToken($bearer[1]);
            if ($data) {
                if (isset($data->mail) && isset($data->id)) {
                    $query = "SELECT totp_key, name, totp_key_validate FROM user WHERE id = :id AND totp_key IS NOT null";
                    $db = new Database();
                    $connection = $db->getConnection();
                    $req = $connection->prepare($query);
                    $req->bindParam(':id', $data->id);
                    $req->execute();

                    if ($req->rowCount() > 0) {
                        $row = $req->fetch();
                        if ($row['totp_key_validate'] == 1) {
                            $secret = $row['totp_key']; // get the secret in the base

                            $otp = new Otp();
                            if ($otp->checkTotp(Encoding::base32DecodeUpper($secret), $key)) {
                                // validate the secret and resend a good token
                                $query = "UPDATE user SET totp_key_validate = true WHERE id = :id";
                                $db = new Database();
                                $connection = $db->getConnection();
                                $req = $connection->prepare($query);
                                $req->bindParam(':id', $data->id);
                                $req->execute();

                                $token = $tokenVerificator->generate($data->id, $data->mail, $row['name']);

                                $data = json_encode(array(
                                    "id" => $data->id,
                                    "mail" => $data->mail,
                                    "token" => $token,
                                ));
                                $response->getBody()->write($data);
                                return $response
                                    ->withHeader('Content-Type', 'application/json')
                                    ->withStatus(200);
                            }
                            // receive a alert message when the user have already validate the secret
                            $data = json_encode(array(
                                "error" => [
                                    "code" => 400,
                                    "message" => "wrong key"
                                ]
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(400);
                        }
                        $data = json_encode(array(
                            "error" => [
                                "code" => 400,
                                "message" => "data key not validate"
                            ]
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(400);
                    }
                    $data = json_encode(array(
                        "error" => [
                            "code" => 400,
                            "message" => "no key params"
                        ]
                    ));
                    $response->getBody()->write($data);
                    return $response
                        ->withHeader('Content-Type', 'application/json')
                        ->withStatus(400);
                }
            }
        }
    }
}