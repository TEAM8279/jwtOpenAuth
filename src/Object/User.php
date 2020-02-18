<?php


namespace App\Object;


use App\Config\Configuration;
use Otp\GoogleAuthenticator;
use Otp\Otp;
use ParagonIE\ConstantTime\Encoding;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Class User contains the action for the user
 * @package App\Object
 */
class User
{
    /**
     * @param Request $request
     * @param Response $response
     * @param $args
     * @return Response
     */
    public function login (Request $request, Response $response, $args) {
        $mail = filter_input(INPUT_POST, 'mail', FILTER_SANITIZE_EMAIL);
        $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

        if (isset($mail) && isset($password)) {
            if (filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                $query = "SELECT ". Configuration::$dbTbUserClIdName .", ". Configuration::$dbTbUserClNameName .", ". Configuration::$dbTbUserClMailName .", ". Configuration::$dbTbUserClPasswordName . ", ". Configuration::$dbTbUserClTotpKeyName ." FROM ". Configuration::$dbTbUserName ." WHERE ". Configuration::$dbTbUserClMailName ." = :mail";
                $db = new Database();
                $connection = $db->getConnection();
                $req = $connection->prepare($query);
                $req->bindParam(':mail', $mail);

                $req->execute();

                if ($req->rowCount() > 0) {
                    $data = $req->fetch();
                    $dbid = $data[Configuration::$dbTbUserClIdName];
                    $dbName = $data[Configuration::$dbTbUserClNameName];
                    $dbmail = $data[Configuration::$dbTbUserClMailName];
                    $dbpassword = $data[Configuration::$dbTbUserClPasswordName];
                    if (password_verify($password, $dbpassword)) {
                        $tokenFactory = new Token();
                        $token = $tokenFactory->generateTemporaryToken($dbmail, $dbid);
                        $data = json_encode(array(
                            "id" => $dbid,
                            "name" => $dbName,
                            "mail" => $dbmail,
                            "token" => $token,
                            "double-check" => $data[Configuration::$dbTbUserClTotpKeyName] !== null
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(200);
                    } // password verify
                } // rowcount
                $data = json_encode(array(
                    "error" => [
                        "code" => "401",
                        "message" => "wrong email or password"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(401);
            } // validation of the mail
            $data = json_encode(array(
                "error" => [
                    "code" => "422",
                    "message" => "Bad email format"
                ]
            ));
            $response->getBody()->write($data);
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(422);
        } // isset mail and passord
        $data = json_encode(array(
            "error" => [
                "code" => "412",
                "message" => "mail or password are missing"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @param $args
     * @return Response
     */
    public function register (Request $request, Response $response, $args) {
        $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
        $mail = filter_input(INPUT_POST, 'mail', FILTER_SANITIZE_EMAIL);
        $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

        if (isset($name) && isset($mail) && isset($password)) {
            if (strlen($password) >= 8) {
                if (filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                    $query = "INSERT INTO ". Configuration::$dbTbUserName ." (" . Configuration::$dbTbUserClNameName .", ". Configuration::$dbTbUserClMailName .", ". Configuration::$dbTbUserClPasswordName . ") VALUES (:name, :mail, :password)";
                    echo $query;
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
                            "mail" => $mail,
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
                } // email validation
                $data = json_encode(array(
                    "error" => [
                        "code" => "422",
                        "message" => "Bad email format"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(422);
            } // password length
            $data = json_encode(array(
                "error" => [
                    "code" => "422",
                    "message" => "Password to short, 8 characters required"
                ]
            ));
            $response->getBody()->write($data);
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(422);
        } // isset password, mail, name
        $data = json_encode(array(
            "error" => [
                "code" => "412",
                "message" => "missing mail, name or password"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @param $args
     * @return Response
     */
    public function totp (Request $request, Response $response, $args)
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if ($bearer[0] == 'Bearer') {
                $tokenVerificator = new Token();
                $data = $tokenVerificator->validateToken($bearer[1]);
                if ($data) {
                    if (isset($data->mail) && isset($data->id)) {
                        // check if the user have already a key
                        $query = "SELECT ". Configuration::$dbTbUserClTotpKeyName .", ". Configuration::$dbTbUserClIdName .", ". Configuration::$dbTbUserClTotpKeyValidateName ." FROM ". Configuration::$dbTbUserName ." WHERE ". Configuration::$dbTbUserClIdName ." = :id AND ". Configuration::$dbTbUserClTotpKeyName ." IS NOT null";
                        $db = new Database();
                        $connection = $db->getConnection();
                        $req = $connection->prepare($query);
                        $req->bindParam(':id', $data->id);
                        $req->execute();
                        if ($req->rowCount() == 0) {
                            $secret = GoogleAuthenticator::generateRandom();
                            $qrCode = GoogleAuthenticator::getQrCodeUrl('totp', Configuration::$OAuthApplicationLabel . " $data->mail", $secret);
                            // update de la base
                            $query = "UPDATE ". Configuration::$dbTbUserName ." SET ". Configuration::$dbTbUserClTotpKeyName ." = '$secret', ". Configuration::$dbTbUserClTotpKeyValidateName ." = false WHERE ". Configuration::$dbTbUserClIdName ." = :id";
                            $db = new Database();
                            $connection = $db->getConnection();
                            $req = $connection->prepare($query);
                            $req->bindParam(':id', $data->id);

                            $req->execute();

                            $data = json_encode(array(
                                "id" => $data->id,
                                "mail" => $data->mail,
                                "token" => $bearer[1],
                                "qr_url" => $qrCode,
                                "secret" => $secret
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(200);

                        } // user have already key
                        $row = $req->fetch();
                        if ($row[Configuration::$dbTbUserClTotpKeyValidateName] == 0) {
                            $secret = GoogleAuthenticator::generateRandom();
                            $qrCode = GoogleAuthenticator::getQrCodeUrl('totp', Configuration::$OAuthApplicationLabel . " $data->mail", $secret);
                            // update de la base
                            $query = "UPDATE ". Configuration::$dbTbUserName ." SET ". Configuration::$dbTbUserClTotpKeyName ." = '$secret', ". Configuration::$dbTbUserClTotpKeyValidateName ." = false WHERE ". Configuration::$dbTbUserClIdName ." = :id";
                            $db = new Database();
                            $connection = $db->getConnection();
                            $req = $connection->prepare($query);
                            $req->bindParam(':id', $data->id);

                            $req->execute();

                            $data = json_encode(array(
                                "id" => $data->id,
                                "mail" => $data->mail,
                                "token" => $bearer[1],
                                "qr_url" => $qrCode,
                                "secret" => $secret
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(200);

                        }

                        $data = json_encode(array(
                            "error" => [
                                "code" => 409,
                                "message" => "the key have already been set"
                            ]
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(409);
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => 403,
                        "message" => "invalid token"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(403);
            }
        }
        $data = json_encode(array(
            "error" => [
                "code" => 412,
                "message" => "bearer token not set"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @param $args
     * @return Response
     */
    public function totpV (Request $request, Response $response, $args) {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);

            if ($bearer[0] == 'Bearer') {
                $tokenVerificator = new Token();
                $data =  $tokenVerificator->validateToken($bearer[1]);
                if (isset($_POST['key'])) {
                    $key = $_POST['key'];


                    if ($data) {


                        if (isset($data->mail) && isset($data->id)) {
                            $query = "SELECT ". Configuration::$dbTbUserClTotpKeyName .", ". Configuration::$dbTbUserClNameName ." , ". Configuration::$dbTbUserClTotpKeyValidateName ." FROM ". Configuration::$dbTbUserName ." WHERE ". Configuration::$dbTbUserClIdName ." = :id AND ". Configuration::$dbTbUserClTotpKeyName ." IS NOT null";
                            $db = new Database();
                            $connection = $db->getConnection();
                            $req = $connection->prepare($query);
                            $req->bindParam(':id', $data->id);
                            $req->execute();


                            if ($req->rowCount() > 0) {
                                $row = $req->fetch();


                                if ($row[Configuration::$dbTbUserClTotpKeyValidateName] == 0) {
                                    $secret = $row[Configuration::$dbTbUserClTotpKeyName]; // get the secret in the base

                                    $otp = new Otp();


                                    if ($otp->checkTotp(Encoding::base32DecodeUpper($secret), $key)) {
                                        // validate the secret and resend a good token
                                        $query = "UPDATE ". Configuration::$dbTbUserName ." SET ". Configuration::$dbTbUserClTotpKeyValidateName ." = true WHERE ". Configuration::$dbTbUserClIdName ." = :id";
                                        $db = new Database();
                                        $connection = $db->getConnection();
                                        $req = $connection->prepare($query);
                                        $req->bindParam(':id', $data->id);
                                        $req->execute();

                                        $token = $tokenVerificator->generate($data->id, $data->mail, $row[Configuration::$dbTbUserClNameName]);

                                        $data = json_encode(array(
                                            "id" => $data->id,
                                            "mail" => $data->mail,
                                            "token" => $token,
                                            "full-login" => true
                                        ));
                                        $response->getBody()->write($data);
                                        return $response
                                            ->withHeader('Content-Type', 'application/json')
                                            ->withStatus(200);
                                    }
                                    $data = json_encode(array(
                                        "error" => [
                                            "code" => 401,
                                            "message" => "wrong key"
                                        ]
                                    ));
                                    $response->getBody()->write($data);
                                    return $response
                                        ->withHeader('Content-Type', 'application/json')
                                        ->withStatus(401);
                                }
                                $data = json_encode(array(
                                    "error" => [
                                        "code" => 422,
                                        "message" => "you ALREADY have validate your secret"
                                    ]
                                ));
                                $response->getBody()->write($data);
                                return $response
                                    ->withHeader('Content-Type', 'application/json')
                                    ->withStatus(422);
                            }
                            $data = json_encode(array(
                                "error" => [
                                    "code" => 401,
                                    "message" => "you don't have set the secret, please use the url for set your secret",
                                    "url" => "/totp"
                                ]
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(401);
                        }
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => 412,
                        "message" => "you missing your key"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(412);
            }
        }
        $data = json_encode(array(
            "error" => [
                "code" => 412,
                "message" => "bearer token not set"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @param $args
     * @return Response
     */
    public function loginValidation (Request $request, Response $response, $args)
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);

            if ($bearer[0] == 'Bearer') {
                $tokenVerificator = new Token();
                $data = $tokenVerificator->validateToken($bearer[1]);
                if ($data) {


                    if (isset($data->mail) && isset($data->id)) {


                        if (isset($_POST['key'])) {
                            $key = $_POST['key'];
                            $query = "SELECT ". Configuration::$dbTbUserClTotpKeyName .", ". Configuration::$dbTbUserClNameName .", ". Configuration::$dbTbUserClTotpKeyValidateName ." FROM ". Configuration::$dbTbUserName ." WHERE ". Configuration::$dbTbUserClIdName ." = :id AND ". Configuration::$dbTbUserClTotpKeyName ." IS NOT null";
                            $db = new Database();
                            $connection = $db->getConnection();
                            $req = $connection->prepare($query);
                            $req->bindParam(':id', $data->id);
                            $req->execute();


                            if ($req->rowCount() > 0) {
                                $row = $req->fetch();


                                if ($row[Configuration::$dbTbUserClTotpKeyValidateName] == 1) {
                                    $secret = $row[Configuration::$dbTbUserClTotpKeyName]; // get the secret in the base

                                    $otp = new Otp();


                                    if ($otp->checkTotp(Encoding::base32DecodeUpper($secret), $key)) {
                                        // validate the secret and resend a good token
                                        $query = "UPDATE ". Configuration::$dbTbUserName ." SET ". Configuration::$dbTbUserClTotpKeyValidateName. " = true WHERE ". Configuration::$dbTbUserClIdName ." = :id";
                                        $db = new Database();
                                        $connection = $db->getConnection();
                                        $req = $connection->prepare($query);
                                        $req->bindParam(':id', $data->id);
                                        $req->execute();

                                        $token = $tokenVerificator->generate($data->id, $data->mail, $row[Configuration::$dbTbUserClNameName]);

                                        $data = json_encode(array(
                                            "id" => $data->id,
                                            "mail" => $data->mail,
                                            "token" => $token,
                                            "full-login" => true
                                        ));
                                        $response->getBody()->write($data);
                                        return $response
                                            ->withHeader('Content-Type', 'application/json')
                                            ->withStatus(200);
                                    }
                                    $data = json_encode(array(
                                        "error" => [
                                            "code" => 401,
                                            "message" => "wrong key"
                                        ]
                                    ));
                                    $response->getBody()->write($data);
                                    return $response
                                        ->withHeader('Content-Type', 'application/json')
                                        ->withStatus(401);
                                }
                                $data = json_encode(array(
                                    "error" => [
                                        "code" => 401,
                                        "message" => "you DONT have validate your secret"
                                    ]
                                ));
                                $response->getBody()->write($data);
                                return $response
                                    ->withHeader('Content-Type', 'application/json')
                                    ->withStatus(401);
                            }
                            $data = json_encode(array(
                                "error" => [
                                    "code" => 403,
                                    "message" => "you don't have set the secret, please use the code setting url",
                                    "url" => "/totp"
                                ]
                            ));
                            $response->getBody()->write($data);
                            return $response
                                ->withHeader('Content-Type', 'application/json')
                                ->withStatus(403);
                        }
                        $data = json_encode(array(
                            "error" => [
                                "code" => 412,
                                "message" => "you missing your key"
                            ]
                        ));
                        $response->getBody()->write($data);
                        return $response
                            ->withHeader('Content-Type', 'application/json')
                            ->withStatus(412);
                    }
                }
                $data = json_encode(array(
                    "error" => [
                        "code" => 403,
                        "message" => "Invalid token"
                    ]
                ));
                $response->getBody()->write($data);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(403);
            }
        }
        $data = json_encode(array(
            "error" => [
                "code" => 412,
                "message" => "bearer token not set"
            ]
        ));
        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }

    public function tokenValidation (Request $request, Response $response, $args) {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $bearer = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if ($bearer[0] == 'Bearer') {
                $tokenVerificator = new Token();
                $data = $tokenVerificator->validateToken($bearer[1]);
                if ($data) {
                    $json = json_encode([
                        "id" => $data->id,
                        "mail" => $data->mail,
                        "full-login" => $data->fullLogin,
                        "iss" => $data->iss,
                        "iat" => $data->iat,
                        "token" => $bearer[1]
                    ]);
                    $response->getBody()->write($json);
                    return $response
                        ->withHeader('Content-Type', 'application/json')
                        ->withStatus(200);
                }
                $json = json_encode([
                    "error" => [
                        "code" => 403,
                        "message" => "the token is invalid"
                    ]
                ]);
                $response->getBody()->write($json);
                return $response
                    ->withHeader('Content-Type', 'application/json')
                    ->withStatus(403);
            }
            $json = json_encode([
                "error" => [
                    "code" => 412,
                    "message" => "This is not a bearer"
                ]
            ]);
            $response->getBody()->write($json);
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(412);
        }
        $json = json_encode([
            "error" => [
                "code" => 412,
                "message" => "You dont have any token"
            ]
        ]);
        $response->getBody()->write($json);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(412);
    }
}
