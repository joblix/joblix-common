<?php

namespace Joblix\Common\Tests;

use Joblix\Common\AuthManager;
use PHPUnit\Framework\TestCase;

class AuthManagerTest extends TestCase
{
    private static $url = 'https://auth.joblix.local/';
    private static $secret = 'abcdefg123';
    private static $domain = 'joblix.local';

    public function testConstructFromParams()
    {
        $manager = new AuthManager(static::$url, static::$secret, static::$domain);

        $this->assertSame(static::$url, $manager->getUrl());
        $this->assertSame(static::$secret, $manager->getPrivateKey());
        $this->assertSame(static::$domain, $manager->getCookieDomain());
    }

    public function testConstructFromEnv()
    {
        putenv('JOBLIX_JWT_LOGIN_URL=' . static::$url);
        putenv('JOBLIX_JWT_PRIVATE_KEY=' . static::$secret);
        putenv('JOBLIX_COOKIE_DOMAIN=' . static::$domain);

        $manager = new AuthManager();

        $this->assertSame(static::$url, $manager->getUrl());
        $this->assertSame(static::$secret, $manager->getPrivateKey());
        $this->assertSame(static::$domain, $manager->getCookieDomain());
    }
}
