<?php

namespace Casbin\Tests\Watcher;

use Casbin\Enforcer;
use PHPUnit\Framework\TestCase;
use Casbin\Model\Model;

/**
 * UtilTest.
 *
 * @author techlee@qq.com
 */
class WatcherExTest extends TestCase
{
    protected $enforcer;
    protected $watcher;
    protected $isCalled;

    public function initWatcher()
    {
        $this->isCalled = false;
        $this->watcher = new SampleWatcherEx();
        $this->enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        $this->enforcer->setWatcher($this->watcher);
    }

    public function testUpdateForSavePolicy()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForSavePolicy(new Model());
        $this->assertTrue($this->isCalled);
    }

    public function testUpdateForAddPolicy()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForAddPolicy('p', 'p');
        $this->assertTrue($this->isCalled);
    }

    public function testUpdateForRemovePolicy()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForRemovePolicy('p', 'p');
        $this->assertTrue($this->isCalled);
    }

    public function testUpdateForRemoveFilteredPolicy()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->updateForRemoveFilteredPolicy('p', 'p', 1);
        $this->assertTrue($this->isCalled);
    }
}
