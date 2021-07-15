<?php

namespace Casbin\Tests\Watcher;

use Casbin\Enforcer;
use PHPUnit\Framework\TestCase;

/**
 * UtilTest.
 *
 * @author techlee@qq.com
 */
class WatcherUpdatableTest extends TestCase
{
    protected $enforcer;
    protected $watcher;
    protected $isCalled;

    public function initWatcher()
    {
        $this->isCalled = false;
        $this->watcher = new SampleWatcherUpdatable();
        $this->enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        $this->enforcer->setWatcher($this->watcher);
    }

    public function testUpdateForUpdatePolicy()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForUpdatePolicy([], []);
        $this->assertTrue($this->isCalled);
    }

    public function testUpdateForUpdatePolicies()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForUpdatePolicies([], []);
        $this->assertTrue($this->isCalled);
    }
}
