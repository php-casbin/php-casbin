<?php

namespace Casbin\Tests\Unit\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\DefaultRoleManager\ConditionalDomainManager;
use Casbin\Rbac\DefaultRoleManager\ConditionalRoleManager;
use Casbin\Rbac\DefaultRoleManager\DomainManager;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Casbin\Util\BuiltinOperations;
use Casbin\Util\Util;
use PHPUnit\Framework\TestCase;

/**
 * RoleManagerTest.
 *
 * @author techlee@qq.com
 */
class RoleManagerTest extends TestCase
{
    protected function testPrintRoles(RoleManager $rm, string $name, array $res)
    {
        $this->assertTrue(Util::setEquals($rm->getRoles($name), $res));
    }

    protected function testPrintUsers(RoleManager $rm, string $name, array $res)
    {
        $this->assertTrue(Util::setEquals($rm->getUsers($name), $res));
    }

    public function testMatch()
    {
        $rm = new RoleManager(3);
        $this->assertEquals($rm->match('u1', 'u1'), true);
        $this->assertEquals($rm->match('u1', 'u2'), false);
        $rm->addMatchingFunc('keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));
        $this->assertEquals($rm->match('u1', '*'), true);
        $this->assertEquals($rm->match('u1', 'u2'), false);

        $dm = new DomainManager(3);
        $this->assertEquals($dm->match('domain1', 'domain1'), true);
        $this->assertEquals($dm->match('domain1', 'domain2'), false);
        $dm->addDomainMatchingFunc('keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));
        $this->assertEquals($dm->match('domain1', '*'), true);
        $this->assertEquals($dm->match('domain1', 'domain2'), false);
    }

    public function testRole()
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

        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g2'), false);
        $this->assertEquals($rm->hasLink('u1', 'g3'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g2'), false);
        $this->assertEquals($rm->hasLink('u2', 'g3'), true);
        $this->assertEquals($rm->hasLink('u3', 'g1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g2'), true);
        $this->assertEquals($rm->hasLink('u3', 'g3'), false);
        $this->assertEquals($rm->hasLink('u4', 'g1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g2'), true);
        $this->assertEquals($rm->hasLink('u4', 'g3'), true);

        $this->testPrintRoles($rm, 'u1', ['g1']);
        $this->testPrintRoles($rm, 'u2', ['g1']);
        $this->testPrintRoles($rm, 'u3', ['g2']);
        $this->testPrintRoles($rm, 'u4', ['g2', 'g3']);
        $this->testPrintRoles($rm, 'g1', ['g3']);
        $this->testPrintRoles($rm, 'g2', []);
        $this->testPrintRoles($rm, 'g3', []);

        $rm->deleteLink('g1', 'g3');
        $rm->deleteLink('u4', 'g2');

        // Current role inheritance tree after deleting the links:
        //             g3    g2
        //           /   \     \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g2'), false);
        $this->assertEquals($rm->hasLink('u1', 'g3'), false);
        $this->assertEquals($rm->hasLink('u2', 'g1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g2'), false);
        $this->assertEquals($rm->hasLink('u2', 'g3'), false);
        $this->assertEquals($rm->hasLink('u3', 'g1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g2'), true);
        $this->assertEquals($rm->hasLink('u3', 'g3'), false);
        $this->assertEquals($rm->hasLink('u4', 'g1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g2'), false);
        $this->assertEquals($rm->hasLink('u4', 'g3'), true);

        $this->testPrintRoles($rm, 'u1', ['g1']);
        $this->testPrintRoles($rm, 'u2', ['g1']);
        $this->testPrintRoles($rm, 'u3', ['g2']);
        $this->testPrintRoles($rm, 'u4', ['g3']);
        $this->testPrintRoles($rm, 'g1', []);
        $this->testPrintRoles($rm, 'g2', []);
        $this->testPrintRoles($rm, 'g3', []);

        $rm = new RoleManager(3);
        $rm->addMatchingFunc('keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));
        $rm->addLink('u1', 'g1');
        $rm->addLink('u1', '*');
        $rm->addLink('u2', 'g2');

        // Current role inheritance tree
        //          g1   g2
        //            \ /  \
        //             *    u2
        //             |
        //             u1
        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g2'), true);
        $this->assertEquals($rm->hasLink('u2', 'g2'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1'), false);
        $this->testPrintRoles($rm, 'u1', ['*', 'u1', 'u2', 'g1', 'g2']);
        $this->testPrintUsers($rm, '*', ['u1']);
    }

    public function testDomainRole()
    {
        $rm = new DomainManager(3);
        $rm->addLink('u1', 'g1', 'domain1');
        $rm->addLink('u2', 'g1', 'domain1');
        $rm->addLink('u3', 'admin', 'domain2');
        $rm->addLink('u4', 'admin', 'domain2');
        $rm->addLink('u4', 'admin', 'domain1');
        $rm->addLink('g1', 'admin', 'domain1');

        // Current role inheritance tree:
        //       domain1:admin    domain2:admin
        //            /       \  /       \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        $this->assertEquals($rm->hasLink('u1', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u1', 'admin', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u1', 'admin', 'domain2'), false);

        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u2', 'admin', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u2', 'admin', 'domain2'), false);

        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u3', 'admin', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u3', 'admin', 'domain2'), true);

        $this->assertEquals($rm->hasLink('u4', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u4', 'admin', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u4', 'admin', 'domain2'), true);

        $rm->deleteLink('g1', 'admin', 'domain1');
        $rm->deleteLink('u4', 'admin', 'domain2');

        // Current role inheritance tree after deleting the links:
        //       domain1:admin    domain2:admin
        //                    \          \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        $this->assertEquals($rm->hasLink('u1', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u1', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u1', 'admin', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u1', 'admin', 'domain2'), false);

        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u2', 'admin', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u2', 'admin', 'domain2'), false);

        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u3', 'admin', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u3', 'admin', 'domain2'), true);

        $this->assertEquals($rm->hasLink('u4', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g1', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u4', 'admin', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u4', 'admin', 'domain2'), false);
    }

    public function testDomainPatternRole()
    {
        $rm = new DomainManager(3);
        $rm->addDomainMatchingFunc('keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));

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

    public function testClear()
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

        $rm->clear();

        // All data is cleared.
        // No role inheritance now.

        $this->assertEquals($rm->hasLink('u1', 'g1'), false);
        $this->assertEquals($rm->hasLink('u1', 'g2'), false);
        $this->assertEquals($rm->hasLink('u1', 'g3'), false);
        $this->assertEquals($rm->hasLink('u2', 'g1'), false);
        $this->assertEquals($rm->hasLink('u2', 'g2'), false);
        $this->assertEquals($rm->hasLink('u2', 'g3'), false);
        $this->assertEquals($rm->hasLink('u3', 'g1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g2'), false);
        $this->assertEquals($rm->hasLink('u3', 'g3'), false);
        $this->assertEquals($rm->hasLink('u4', 'g1'), false);
        $this->assertEquals($rm->hasLink('u4', 'g2'), false);
        $this->assertEquals($rm->hasLink('u4', 'g3'), false);
    }



    public function testAllMatchingFunc()
    {
        $rm = new RoleManager(10);
        $rm->addMatchingFunc('keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));
        $rm->addDomainMatchingFunc('keyMatch2', fn(string $key1, string $key2) => BuiltinOperations::keyMatch2($key1, $key2));

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
        $rm->addMatchingFunc('regexMatch', fn(string $key1, string $key2) => BuiltinOperations::regexMatch($key1, $key2));

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

    public function testDomainMatchingFuncWithDifferentDomain()
    {
        $rm = new DomainManager(10);
        $rm->addDomainMatchingFunc('keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));

        $rm->addLink('alice', 'editor', '*');
        $rm->addLink('editor', 'admin', 'domain1');

        $this->assertEquals($rm->hasLink('alice', 'admin', 'domain1'), true);
        $this->assertEquals($rm->hasLink('alice', 'admin', 'domain2'), false);
    }

    public function testTemporaryRole()
    {
        $rm = new RoleManager(10);
        $rm->addMatchingFunc('regexMatch', fn(string $key1, string $key2) => BuiltinOperations::regexMatch($key1, $key2));

        $rm->addLink('u\d+', 'user');

        for ($i = 0; $i < 10; $i++) {
            $this->assertEquals($rm->hasLink(sprintf('u%d', $i), 'user'), true);
        }

        $this->testPrintUsers($rm, 'user', ['u\d+']);
        $this->testPrintRoles($rm, 'u1', ['user']);

        $rm->addLink('u1', 'manager');

        for ($i = 10; $i < 20; $i++) {
            $this->assertEquals($rm->hasLink(sprintf('u%d', $i), 'manager'), true);
        }

        $this->testPrintUsers($rm, 'user', ['u\d+', 'u1']);
        $this->testPrintRoles($rm, 'u1', ['user', 'manager']);
    }

    public function testMaxHierarchyLevel()
    {
        $rm = new RoleManager(1);
        $rm->addLink("level0", "level1");
        $rm->addLink("level1", "level2");
        $rm->addLink("level2", "level3");

        $this->assertTrue($rm->hasLink("level0", "level0"));
        $this->assertTrue($rm->hasLink("level0", "level1"));
        $this->assertFalse($rm->hasLink("level0", "level2"));
        $this->assertFalse($rm->hasLink("level0", "level3"));
        $this->assertTrue($rm->hasLink("level1", "level2"));
        $this->assertFalse($rm->hasLink("level1", "level3"));

        $rm = new RoleManager(2);
        $rm->addLink("level0", "level1");
        $rm->addLink("level1", "level2");
        $rm->addLink("level2", "level3");

        $this->assertTrue($rm->hasLink("level0", "level0"));
        $this->assertTrue($rm->hasLink("level0", "level1"));
        $this->assertTrue($rm->hasLink("level0", "level2"));
        $this->assertFalse($rm->hasLink("level0", "level3"));
        $this->assertTrue($rm->hasLink("level1", "level2"));
        $this->assertTrue($rm->hasLink("level1", "level3"));
    }

    public function testConditionalRoleManager()
    {
        $rm = new ConditionalRoleManager(10);
        $rm->addLink('u1', 'g1');
        $rm->addLink('u2', 'g1');
        $rm->addLink('u3', 'g2');
        $rm->addLinkConditionFunc('u1', 'g1', fn() => true);
        $rm->addLinkConditionFunc('u2', 'g1', fn() => false);
        $rm->addLinkConditionFunc('u3', 'g2', function () {
            throw new CasbinException('error func');
        });
        $rm->setLinkConditionFuncParams('u1', 'g1');
        $rm->setLinkConditionFuncParams('u2', 'g1');
        $rm->setLinkConditionFuncParams('u3', 'g2');

        $this->assertEquals($rm->hasLink('u1', 'g1'), true);
        $this->assertEquals($rm->hasLink('u2', 'g1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g2'), false);

        $rm->deleteLink('u1', 'g1');
        $this->assertEquals($rm->hasLink('u1', 'g1'), false);
    }

    public function testConditionalDomainManager()
    {
        $rm = new ConditionalDomainManager(10);
        $rm->addDomainMatchingFunc('keyMatch', fn(string $key1, string $key2) => BuiltinOperations::keyMatch($key1, $key2));
        $rm->addLink('u1', 'g1', '*');
        $rm->addLink('u2', 'g1', 'domain1');
        $rm->addLink('u3', 'g2', 'domain2');
        $rm->addLink('g1', 'root', 'domain1');
        $rm->addDomainLinkConditionFunc('u1', 'g1', '*', fn() => true);
        $rm->addDomainLinkConditionFunc('u2', 'g1', 'domain1', fn() => false);
        $rm->addDomainLinkConditionFunc('u3', 'g2', 'domain2', function () {
            throw new CasbinException('error func');
        });
        $rm->setDomainLinkConditionFuncParams('u1', 'g1', '*');
        $rm->setDomainLinkConditionFuncParams('u2', 'g1', 'domain1');
        $rm->setDomainLinkConditionFuncParams('u3', 'g2', 'domain2');

        $this->assertEquals($rm->hasLink('u1', 'root', 'domain1'), true);
        $this->assertEquals($rm->hasLink('u1', 'root', 'domain2'), false);
        $this->assertEquals($rm->hasLink('u2', 'g1', 'domain1'), false);
        $this->assertEquals($rm->hasLink('u3', 'g2', 'domain2'), false);

        $rm->deleteLink('u1', 'g1', '*');
        $this->assertEquals($rm->hasLink('u1', 'root', 'domain1'), false);
    }
}
