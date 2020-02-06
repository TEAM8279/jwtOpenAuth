<?php


namespace App\Object;



use App\Config\Configuration;
use Firebase\JWT\JWT;

/**
 * Class Token is used for generate and validate Json Web Token
 * @package App\Object
 */
class Token
{
    /**
     * @var string contains the key for encrypt the token
     */
    private $key = "";

    /**
     * Token constructor.set the token key from the configuration
     */
    public function __construct()
    {
        $this->key = Configuration::$tokenKey;
    }

    /**
     * generate a temporary token used for validate the dbl auth
     * @param $usermail string contains the mail of the user
     * @param $userId int contains the id of the user
     * @return string a json web token
     */
    public function generateTemporaryToken ($usermail, $userId) {
        $payload = array(
            "id" => $userId,
            "mail" => $usermail,
            "full-login" => false
        );
        return JWT::encode($payload, $this->key);
    }

    /**
     * valide a token
     * @param $token string is the token you want validate
     * @return bool|object false if the token is corrupted or the data of the token
     */
    public function validateToken ($token) {
        try {
            return JWT::decode($token, $this->key, array('HS256'));
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * generate a token with full access
     * @param $id int contains the id of the user
     * @param $mail string contains the mail of the user
     * @param $name string contains the name of the user
     * @return string the json web token with a full login access
     */
    public function generate($id, $mail, $name)
    {
        $payload = array(
            "id" => $id,
            "mail" => $mail,
            "name" => $name,
            "full-login" => true
        );
        return JWT::encode($payload, $this->key);
    }
}
