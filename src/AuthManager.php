<?php

namespace Joblix\Common;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

class AuthManager
{
    /**
     * @var string $cookie_domain
     */
    private $cookie_domain;

    /**
     * @var string $private_key
     */
    private $private_key;

    /**
     * @var string $auth_url
     */
    private $url;

    public function __construct($url = null, $private_key = null, $cookie_domain = null)
    {
        if (empty($cookie_domain)) {
            $cookie_domain = getenv('JOBLIX_COOKIE_DOMAIN');
        }
        if ($cookie_domain) {
            $this->setCookieDomain($cookie_domain);
        }

        if (empty($private_key)) {
            $private_key = getenv('JOBLIX_JWT_PRIVATE_KEY');
        }
        if ($private_key) {
            $this->setPrivateKey($private_key);
        }

        if (empty($url)) {
            $url = getenv('JOBLIX_JWT_LOGIN_URL');
        }
        if ($url) {
            $this->setUrl($url);
        }
    }

    /**
     * @return string
     */
    public function getCookieDomain()
    {
        return $this->cookie_domain;
    }

    /**
     * @param string $cookie_domain
     * @return $this
     */
    public function setCookieDomain(string $cookie_domain)
    {
        $cookie_domain_filtered = filter_var($cookie_domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
        if (!$cookie_domain_filtered) {
            throw new \DomainException('Invalid cookie domain: ' . $cookie_domain);
        }

        $this->cookie_domain = $cookie_domain_filtered;
        return $this;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->private_key;
    }

    /**
     * @param string $private_key
     * @return $this
     */
    public function setPrivateKey(string $private_key)
    {
        $this->private_key = $private_key;
        return $this;
    }

    /**
     * @return string
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param string $url
     * @return $this
     */
    public function setUrl(string $url)
    {
        $url_filtered = filter_var($url, FILTER_VALIDATE_URL);
        if (!$url_filtered) {
            throw new \DomainException('Invalid Login URL: ' . $url);
        }

        $this->url = $url_filtered;
        return $this;
    }

    /**
     * @param string $tokenString
     * @return Token
     */
    public function authenticate(string $tokenString = null)
    {
        if (!$tokenString && !empty($_GET['authmanager_token'])) {
            $tokenString = $_GET['authmanager_token'];
        }

        if ($tokenString) {
            $token = $this->parseToken($tokenString);
            setcookie('authmanager_token', $tokenString, $token->getClaim('exp'), '/', $this->cookie_domain);
        } elseif (!empty($_COOKIE['authmanager_token'])) {
            $token = $this->parseToken($_COOKIE['authmanager_token']);
        } else {
            $this->redirectToLogin($this->getCurrentUrl());
        }

        if (!$this->validateToken($token)) {
            setcookie('authmanager_token', '', time() - 3600);
            $this->redirectToLogin($this->getCurrentUrl());
        }

        return $token;
    }

    /**
     * @param string $role
     * @return bool
     */
    public function hasRole(string $role)
    {
        $token = $this->authenticate();
        return in_array($role, $token->getClaim('roles'));
    }

    /**
     * @param string $permission
     * @return bool
     */
    public function hasPermission(string $permission)
    {
        $token = $this->authenticate();
        return in_array($permission, $token->getClaim('permisions'));
    }

    /**
     * @return bool
     */
    public function isLoggedIn()
    {
        if (empty($_COOKIE['token'])) {
            return false;
        }

        $token = $this->parseToken($_COOKIE['token']);
        if (!$this->validateToken($token)) {
            return false;
        }

        return true;
    }

    /**
     * @param string $tokenString
     * @return Token
     */
    public function parseToken(string $tokenString)
    {
        return (new Parser())->parse((string) $tokenString);
    }

    /**
     * @param string|null $backUrl
     * @return void
     */
    public function redirectToLogin(string $backUrl = null)
    {
        $query = parse_url($backUrl, PHP_URL_QUERY);
        if ($query) {
            $backUrl .= '&authmanager_token=JWT_TOKEN';
        } else {
            $backUrl .= '?authmanager_token=JWT_TOKEN';
        }

        header('Location: ' . $this->url . '?to=' . urlencode($backUrl), true, 302);
        exit;
    }

    /**
     * @param Token $token
     * @return bool
     */
    public function validateToken(Token $token)
    {
        $signer = new Sha256();
        $time = time();

        if (!$token->verify($signer, $this->private_key)) {
            return false;
        }

        $data = new ValidationData($time, 30);
        if (!$token->validate($data)) {
            return false;
        }

        return true;
    }

    /**
     * @return string
     */
    protected function getCurrentUrl()
    {
        if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
            $link = "https";
        else
            $link = "http";

        $link .= "://";
        $link .= $_SERVER['HTTP_HOST'];
        $link .= $_SERVER['REQUEST_URI'];

        return $link;
    }
}
