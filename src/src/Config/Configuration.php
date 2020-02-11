<?php


namespace App\Config;

/**
 * Class Configuration configuration file for the api
 * @package App\Config
 */
class Configuration
{
    /**
     * @var string contains the name of the database
     */
    public static $dbName = "auth";
    /**
     * @var string contains the host of the database
     */
    public static $dbhost = "localhost";
    /**
     * @var string contains the user of the database
     */
    public static $dbuser = "admin";
    /**
     * @var string contains the password of the user of the database
     */
    public static $dbpassword = "Youpla";

    /**
     * @var string contains the start of the label for the dblcheck app
     * Example: [start] + [usermail] = Oauth martitom for tom@martitom.ch
     */
    public static $OAuthApplicationLabel = "OAuth martitom for";

    /**
     * @var string contains the secret key for encryption of the token
     * I think 1024 bits is good.
     */
    public static $tokenKey = "example";
    /**
     * @var string contains the token iss
     */
    public static $tokenIss = "https://auth.martitom.ch";
}
