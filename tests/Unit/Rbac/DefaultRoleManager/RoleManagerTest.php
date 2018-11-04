<?php

namespace Casbin\Tests\Unit\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
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
}
