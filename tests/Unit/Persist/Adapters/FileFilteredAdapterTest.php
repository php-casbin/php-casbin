<?php

namespace Casbin\Tests\Unit\Persist\Adapters;

use Casbin\Exceptions\CasbinException;
use Casbin\Model\Model;
use Casbin\Persist\Adapters\FileFilteredAdapter;
use Casbin\Persist\Adapters\Filter;
use PHPUnit\Framework\TestCase;

/**
 * FileFilteredAdapterTest.
 *
 * @author techlee@qq.com
 */
class FileFilteredAdapterTest extends TestCase
{
    private $modelAndPolicyPath = __DIR__ . '/../../../../examples';

    public function testFileFilteredPolicy()
    {
        $adapter = new FileFilteredAdapter($this->modelAndPolicyPath . '/rbac_with_domains_policy.csv');
        $this->assertTrue($adapter->isFiltered());

        $m = new Model();
        $m->loadModel($this->modelAndPolicyPath . '/rbac_with_domains_model.conf');

        $adapter->loadFilteredPolicy($m, null);
        $this->assertFalse($adapter->isFiltered());
        $this->assertTrue($m->hasPolicy('p', 'p', ['admin', 'domain1', 'data1', 'read']));
        $this->assertTrue($m->hasPolicy('p', 'p', ['admin', 'domain2', 'data2', 'read']));

        $m->clearPolicy();

        $filter = new Filter();
        $filter->p = ['', 'domain1'];
        $filter->g = ['', '', 'domain1'];

        $adapter->loadFilteredPolicy($m, $filter);
        $this->assertTrue($adapter->isFiltered());

        $this->assertTrue($m->hasPolicy('p', 'p', ['admin', 'domain1', 'data1', 'read']));
        $this->assertFalse($m->hasPolicy('p', 'p', ['admin', 'domain2', 'data2', 'read']));

        try {
            $adapter->savePolicy($m);
        } catch (\Throwable $th) {
            $this->assertInstanceOf(CasbinException::class, $th);
        }

        try {
            $adapter->loadFilteredPolicy($m, new \stdClass());
        } catch (\Throwable $th) {
            $this->assertInstanceOf(CasbinException::class, $th);
        }

        try {
            $adapter = new FileFilteredAdapter('');
            $adapter->loadFilteredPolicy($m, $filter);
        } catch (\Throwable $th) {
            $this->assertInstanceOf(CasbinException::class, $th);
        }
    }
}
