# jwtOpenAuth

JwtOpenAuth is a two-factor authentication api that can be implemented very quickly and easily based on SlimFramework.

## Prerequisite

A  database with an user table with some columns :

column | type | description
--- | --- | ---
id | int | contain the id of the user
name | string 254 | contain the name of the user
mail | string 254 | contain the mail of the user
password | string 254 | contain the password of the user
totp_key | string 16 | contain the totp key
totp_key_validate | boolean | contain if the totp key has been validated

## Install the application

First, we have to install the application on your computer. Replace ``` [my-app-name]``` by the name of your application. 

`````` 
composer create-project tommarti/jwtopenauth [my-app-name]
``````

To run the application in development, run these commands:

```
cd [my-app-name]
composer start
```

To run your application's tests, run this command:

``````
composer test
``````

## Configuration

Go in src/Config/Configuration.php in the project and configure your application for working with your infrastructure.

1. Configure the database info
   * db name
   * db host
   * db user
   * db password
   * db user table name
   * db id column name
   * db name column name
   * db mail column name
   * db password column name
   * db totp_key column name
   * db totp_key_validate column name
2. Configure the application label
3. Configure the token info
   * token key
   * token iss

## Generate the api documentation

In progress...