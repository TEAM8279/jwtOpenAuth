<?php


namespace App\Object;


use Firebase\JWT\JWT;

class Token
{
    private $key = "example";

    public function generateTemporaryToken ($usermail, $userId) {
        $payload = array(
            "id" => $userId,
            "mail" => $usermail
        );
        return JWT::encode($payload, $this->key);
    }

    public function validateToken ($token) {
        try {
            return JWT::decode($token, $this->key, array('HS256'));
        } catch (\Exception $e) {
            return false;
        }
    }

    public function generate($id, $mail, $name)
    {
        $payload = array(
            "id" => $id,
            "mail" => $mail,
            "name" => $name
        );
        return JWT::encode($payload, $this->key);
    }
}
