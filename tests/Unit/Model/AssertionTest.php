<?php

namespace Casbin\Tests\Unit\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Model\Assertion;
use Casbin\Model\Policy;
use Casbin\Rbac\DefaultRoleManager\ConditionalRoleManager;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Mockery;
use PHPUnit\Framework\TestCase;

/**
 * AssertionTest.
 *
 * @author 169898084@qq.com
 */
class AssertionTest extends TestCase
{
    public function testBuildRoleLinks()
    {
        $rm = Mockery::mock(RoleManager::class);
        $rm->shouldReceive('addLink')
            ->once()
            ->with('alice', 'admin');

        $ast = new Assertion();
        $ast->policy = [['alice']];
        $ast->value = '_';
        /** @var RoleManager $rm */
        try {
            $ast->buildRoleLinks($rm);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('the number of "_" in role definition should be at least 2', $e->getMessage());
        }

        $ast->value = '_, _';
        try {
            $ast->buildRoleLinks($rm);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('grouping policy elements do not meet role definition', $e->getMessage());
        }

        $ast->policy = [['alice', 'admin', 'root']];
        $ast->buildRoleLinks($rm);
    }

    public function testBuildConditionalRoleLinks()
    {
        $condRm = Mockery::mock(ConditionalRoleManager::class);
        $condRm->shouldReceive('addLink')
            ->once()
            ->with('alice', 'admin');
        $condRm->shouldReceive('setLinkConditionFuncParams')
            ->once()
            ->with('alice', 'admin');

        $ast = new Assertion();
        $ast->policy = [['alice']];
        $ast->value = '_';
        /** @var ConditionalRoleManager $condRm */
        try {
            $ast->buildConditionalRoleLinks($condRm);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('the number of "_" in role definition should be at least 2', $e->getMessage());
        }

        $ast->value = '_, _';
        try {
            $ast->buildConditionalRoleLinks($condRm);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('grouping policy elements do not meet role definition', $e->getMessage());
        }

        $ast->policy = [['alice', 'admin', 'root']];
        $ast->tokens = ['alice', 'admin', 'root'];
        $ast->buildConditionalRoleLinks($condRm);
    }

    public function testBuildIncrementalRoleLinks()
    {
        $rm = Mockery::mock(RoleManager::class);
        $rm->shouldReceive('addLink')
            ->once()
            ->with('alice', 'admin');
        $rm->shouldReceive('deleteLink')
            ->once()
            ->with('alice', 'admin');

        $ast = new Assertion();
        $ast->policy = [['alice']];
        $ast->value = '_';
        /** @var RoleManager $rm */
        try {
            $ast->buildIncrementalRoleLinks($rm, Policy::POLICY_ADD, [['alice']]);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('the number of "_" in role definition should be at least 2', $e->getMessage());
        }

        $ast->value = '_, _';
        try {
            $ast->buildIncrementalRoleLinks($rm, Policy::POLICY_ADD, [['alice']]);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('grouping policy elements do not meet role definition', $e->getMessage());
        }

        $ast->buildIncrementalRoleLinks($rm, Policy::POLICY_ADD, [['alice', 'admin', 'root']]);
        $ast->buildIncrementalRoleLinks($rm, Policy::POLICY_REMOVE, [['alice', 'admin', 'root']]);
    }


    public function testBuildIncrementalConditionalRoleLinks()
    {
        $condRm = Mockery::mock(ConditionalRoleManager::class);
        $condRm->shouldReceive('addLink')
            ->once()
            ->with('alice', 'admin');
        $condRm->shouldReceive('setLinkConditionFuncParams')
            ->once()
            ->with('alice', 'admin');
        $condRm->shouldReceive('deleteLink')
            ->once()
            ->with('alice', 'admin');

        $ast = new Assertion();
        $ast->policy = [['alice']];
        $ast->value = '_';
        /** @var ConditionalRoleManager $condRm */
        try {
            $ast->buildIncrementalConditionalRoleLinks($condRm, Policy::POLICY_ADD, [['alice']]);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('the number of "_" in role definition should be at least 2', $e->getMessage());
        }

        $ast->value = '_, _';
        try {
            $ast->buildIncrementalConditionalRoleLinks($condRm, Policy::POLICY_ADD, [['alice']]);
            $this->fail('Expected CasbinException to be thrown');
        } catch (CasbinException $e) {
            $this->assertEquals('grouping policy elements do not meet role definition', $e->getMessage());
        }

        $ast->tokens = ['alice', 'admin', 'root'];
        $ast->buildIncrementalConditionalRoleLinks($condRm, Policy::POLICY_ADD, [['alice', 'admin', 'root']]);
        $ast->buildIncrementalConditionalRoleLinks($condRm, Policy::POLICY_REMOVE, [['alice', 'admin', 'root']]);
    }
}
