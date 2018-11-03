<?php

namespace Casbin\Tests\Feature;

use Casbin\Model\Model;
use Casbin\Persist\Adapters\FileAdapter;
use PHPUnit\Framework\TestCase;

/**
 * EnforcerTest.
 *
 * @author techlee@qq.com
 */
class FileAdapterTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__.'/../../../../examples/modelandpolicy';

    public function testSavePolicy()
    {
        $adapter = new FileAdapter(__DIR__.'/basic_policy_test.csv');
        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath.'/basic_model.conf');

        $rule = ['admin', 'domain1', 'data1', 'read2'];

        $m->addPolicy('p', 'p', $rule);

        $res = $adapter->savePolicy($m);

        $this->assertFalse(false === $res);
    }
}
