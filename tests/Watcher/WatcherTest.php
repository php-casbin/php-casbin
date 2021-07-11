<?php

namespace Casbin\Tests\Watcher;

use Casbin\Enforcer;
use Exception;
use PHPUnit\Framework\TestCase;

/**
 * UtilTest.
 *
 * @author techlee@qq.com
 */
class WatcherTest extends TestCase
{
    protected $enforcer;
    protected $watcher;
    protected $isCalled;

    public function initWatcher()
    {
        $this->isCalled = false;
        $this->watcher = new SampleWatcher();
        $this->enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        $this->enforcer->setWatcher($this->watcher);
    }

    public function testUpdate()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->watcher->update();
        $this->assertTrue($this->isCalled);
    }
}
