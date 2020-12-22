<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\CachedEnforcer;

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

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e->removePolicy('alice', 'data1', 'read');

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));

        $e->invalidateCache();

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data1', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    public function testEnableCache()
    {
        $e = new CachedEnforcer($this->modelAndPolicyPath . '/basic_model.conf', $this->modelAndPolicyPath . '/basic_policy.csv');

        $e->enableCache(false);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));

        $e->removePolicy('alice', 'data1', 'read');

        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
    }
}
