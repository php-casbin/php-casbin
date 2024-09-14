<?php

namespace Casbin\Tests\Unit;

use Casbin\Contracts\CacheableParam;
use PHPUnit\Framework\TestCase;
use Casbin\CachedEnforcer;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * CachedEnforcerTest.
 *
 * @author techlee@qq.com
 */
class CachedEnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../examples';

    public function testEnforce()
    {
        $e = new CachedEnforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e->setExpireTime(60);
 
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e->removePolicy('alice', 'data1', 'read');
        $this->assertFalse($e->removePolicy('alice', 'data1', 'read'));

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e = new CachedEnforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');
        $e->enableCache(false);
 
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e = new CachedEnforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->setCache(new ArrayAdapter());

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removePolicies([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
        ]);
        $this->assertFalse($e->removePolicies([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
        ]));

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e = new CachedEnforcer($this->modelAndPolicyPath . '/rbac_model.conf', $this->modelAndPolicyPath . '/rbac_policy.csv');
        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->clearPolicy();

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e->invalidateCache();
    }

    public function testGetCacheKey()
    {
        $e = new CachedEnforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $this->assertEquals('alice$$data1$$read$$', $e->getCacheKey('alice', 'data1', 'read'));
        $this->assertEquals('alice$$data1$$read$$', $e->getCacheKey(new class() implements CacheableParam {
            public function getCacheKey(): string
            {
                return 'alice';
            }
        }, 'data1', 'read'));
        $this->assertEquals('', $e->getCacheKey('alice', 'data1', true));
    }
}
