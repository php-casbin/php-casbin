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
    /**
     * @var Enforcer
     */
    protected $enforcer;

    /**
     * @var SampleWatcher
     */
    protected $watcher;

    /**
     * @var bool
     */
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

    public function testSelfModify()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->enforcer->addPolicy('eva', 'data', 'read');
        $this->assertTrue($this->isCalled);

        $this->isCalled = false;
        $this->enforcer->selfAddPolicy('p', 'p', ['eva', 'data', 'write']);
        $this->assertFalse($this->isCalled);
    }

    public function testSelfModifyEx()
    {
        $this->initWatcher();
        $this->watcher->setUpdateCallback(function () {
            $this->isCalled = true;
        });
        $this->enforcer->selfAddPolices('p', 'p', [['user1', 'data1', 'read']]);
        $this->assertFalse($this->isCalled);
        $this->enforcer->selfAddPolicesEx('p', 'p', [['user1', 'data1', 'read'], ['user2', 'data2', 'read']]);
        $this->assertFalse($this->isCalled);
    }
}
