<?php

namespace Casbin\Tests\Unit\Config;

use Casbin\Config\Config;
use Casbin\Exceptions\CasbinException;
use PHPUnit\Framework\TestCase;

/**
 * ConfigTest.
 *
 * @author techlee@qq.com
 */
class ConfigTest extends TestCase
{
    public function testNewConfig()
    {
        $cfg = Config::newConfig(__DIR__ . '/test.ini');
        $this->getAndSetConfig($cfg);
    }

    public function testNewConfigFromText()
    {
        $cfg = Config::newConfigFromText(file_get_contents(__DIR__ . '/test.ini'));
        $this->getAndSetConfig($cfg);

        try {
            $cfg = Config::newConfigFromText(<<<'EOT'
[mysql]
mysql.dev.host = 127.0.0.1
mysql.dev.user
EOT
            );
        } catch (\Exception $e) {
            $this->assertTrue($e instanceof CasbinException);
        }
    }

    private function getAndSetConfig(Config $cfg)
    {
        // $cfg = Config::newConfigFromText(file_get_contents(__DIR__.'/test.ini'));
        $this->assertEquals('act.wiki', $cfg->getString('url'));

        $v = $cfg->getStrings('redis::redis.key');
        $this->assertTrue(2 == \count($v) && 'push1' == $v[0] && 'push2' == $v[1]);

        $v = $cfg->getString('mysql::mysql.dev.host');
        $this->assertEquals('127.0.0.1', $v);

        $cfg->set('other::key1', 'new test key');
        $v = $cfg->getString('other::key1');
        $this->assertEquals('new test key', $v);

        $v = $cfg->getString('multi1::name');
        $this->assertEquals('r.sub==p.sub&&r.obj==p.obj', $v);

        $v = $cfg->getString('multi2::name');
        $this->assertEquals('r.sub==p.sub&&r.obj==p.obj', $v);

        $v = $cfg->getString('multi3::name');
        $this->assertEquals('r.sub==p.sub&&r.obj==p.obj', $v);

        $v = $cfg->getString('multi4::name');
        $this->assertEquals('', $v);

        $v = $cfg->getString('multi5::name');
        $this->assertEquals('r.sub==p.sub&&r.obj==p.obj', $v);

        $v = $cfg->getStrings('noexist');
        $this->assertEquals([], $v);

        try {
            $cfg->set('', '');
        } catch (\Exception $e) {
            $this->assertTrue($e instanceof CasbinException);
        }

        $cfg->set('nosec', 'nosec');
        $this->assertEquals('nosec', $cfg->getString('nosec'));
    }
}
