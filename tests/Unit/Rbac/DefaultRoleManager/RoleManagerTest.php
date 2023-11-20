<?php

namespace Casbin\Tests\Unit\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Casbin\Util\BuiltinOperations;
use PHPUnit\Framework\TestCase;

/**
 * RoleManagerTest.
 *
 * @author techlee@qq.com
 */
class RoleManagerTest extends TestCase
{
    public function testAddLink()
    {
        $rm = new RoleManager(3);

        $rm->addLink('u1', 'g1');

        $res = $rm->hasLink('u1', 'g1');

        $this->assertTrue($res);
    }

    public function testDeleteLink()
    {
        $rm = new RoleManager(3);

        try {
            $rm->deleteLink('u1', 'g1');
        } catch (\Exception $e) {
            $this->assertTrue($e instanceof CasbinException);
        }

        $rm->addLink('u1', 'g1');
        $res = $rm->hasLink('u1', 'g1');
        $this->assertTrue($res);

        $rm->deleteLink('u1', 'g1');
        $res = $rm->hasLink('u1', 'g1');
        $this->assertFalse($res);
    }

    public function testGetRoles()
    {
        $rm = new RoleManager(3);

        $rm->addLink('u1', 'g1');
        $rm->addLink('u2', 'g1');
        $rm->addLink('u3', 'g2');
        $rm->addLink('u4', 'g2');
        $rm->addLink('u4', 'g3');
        $rm->addLink('g1', 'g3');
        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        $this->assertEquals($rm->getRoles('u1'), ['g1']);
        $this->assertEquals($rm->getRoles('u4'), ['g2', 'g3']);
    }

    public function testGetUsers()
    {
        $rm = new RoleManager(3);
        $rm->addLink('u1', 'g1');
        $rm->addLink('u2', 'g1');
        $rm->addLink('u3', 'g2');
        $rm->addLink('u4', 'g2');
        $rm->addLink('u4', 'g3');
        $rm->addLink('g1', 'g3');
        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2
        $this->assertEquals($rm->getUsers('g1'), ['u1', 'u2']);

        $this->assertEquals($rm->getUsers('g3'), ['g1', 'u4']);
    }

    public function testDomainPatternRole()
    {
        $rm = new RoleManager(10);
        $rm->addDomainMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });

        $rm->addLink('u1', 'g1', 'domain1');
        $rm->addLink('u2', 'g1', 'domain2');
        $rm->addLink('u3', 'g1', '*');
        $rm->addLink('u4', 'g2', 'domain3');
        // Current role inheritance tree after deleting the links:
        //       domain1:g1    domain2:g1           domain3:g2
        //         /      \    /      \                 |
        //   domain1:u1    *:g1     domain2:u2      domain3:u4
        //                  |
        //                 *:u3
        $this->assertEquals($rm->hasLink('u1', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain2'), true);
        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain2'), true);
        $this->assertEquals($rm->hasLink('u1', 'g2', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g2', 'domain3'), true);
        $this->assertEquals($rm->hasLink('u3', 'g2', 'domain3'), false);

        $this->assertEquals($rm->getRoles('u3', 'domain1'), ['g1']);
        $this->assertEquals($rm->getRoles('u1', 'domain1'), ['g1']);
        $this->assertEquals($rm->getRoles('u3', 'domain2'), ['g1']);
        $this->assertEquals($rm->getRoles('u1', 'domain2'), []);
        $this->assertEquals($rm->getRoles('u4', 'domain3'), ['g2']);
    }

    public function testAllMatchingFunc()
    {
        $rm = new RoleManager(10);
        $rm->addMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });
        $rm->addDomainMatchingFunc('keyMatch2', function (string $key1, string $key2) {
            return BuiltinOperations::keyMatch2($key1, $key2);
        });

        $rm->addLink('/book/:id', 'book_group', '*');
        // Current role inheritance tree after deleting the links:
        //       *:book_group
        //           |
        //       *:/book/:id
        $this->assertEquals($rm->hasLink('/book/1', 'book_group', 'domain1'), true);
        $this->assertEquals($rm->hasLink('/book/2', 'book_group', 'domain1'), true);
    }

    public function testMatchingFuncOrder()
    {
        $rm = new RoleManager(10);
        $rm->addMatchingFunc('regexMatch', function (string $key1, string $key2) {
            return BuiltinOperations::regexMatch($key1, $key2);
        });

        $rm->addLink('g\\d+', 'root');
        $rm->addLink('u1', 'g1');
        $this->assertEquals($rm->hasLink('u1', 'root'), true);

        $rm->clear();

        $rm->AddLink('u1', 'g1');
        $rm->AddLink('g\\d+', 'root');
        $this->assertEquals($rm->hasLink('u1', 'root'), true);

        $rm->clear();

        $rm->AddLink('u1', 'g\\d+');
        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
    }
}
