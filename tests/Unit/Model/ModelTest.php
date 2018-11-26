<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Enforcer;
use Casbin\Model\Model;
use PHPUnit\Framework\TestCase;

/**
 * ModelTest.
 *
 * @author techlee@qq.com
 */
class ModelTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../../examples';

    public function testLoadModelFromText()
    {
        $text = <<<'EOT'
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
EOT;
        $m = new Model();
        $m->loadModelFromText($text);

        $rule = ['alice', 'data1', 'read'];
        $m->addPolicy('p', 'p', $rule);
        $rule = ['bob', 'data2', 'write'];
        $m->addPolicy('p', 'p', $rule);

        $e = new Enforcer($m);

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
    }
}
