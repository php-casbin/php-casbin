<?php

namespace Casbin\Tests\Unit;

use Casbin\Enforcer;
use Casbin\Persist\Adapters\FileAdapter;
use PHPUnit\Framework\TestCase;

/**
 * EnforcerTest.
 *
 * @author techlee@qq.com
 */
class EnforcerTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../examples';

    public function testSetModel()
    {
        $e = new Enforcer();

        $m = Enforcer::newModel(
            <<<'EOT'
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
EOT
        );
        $e->setModel($m);

        $adapter = new FileAdapter($this->modelAndPolicyPath.'/basic_policy.csv');
        $e->setAdapter($adapter);

        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }

    public function testSetAdapter()
    {
        $e = new Enforcer($this->modelAndPolicyPath.'/basic_model.conf');

        $adapter = new FileAdapter($this->modelAndPolicyPath.'/basic_policy.csv');
        $e->setAdapter($adapter);

        $e->loadPolicy();

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
    }
}
