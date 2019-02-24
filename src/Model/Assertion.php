<?php

namespace Casbin\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\RoleManager;
use Casbin\Log\Log;

/**
 * Class Assertion
 * represents an expression in a section of the model.
 *
 * @author techlee@qq.com
 */
class Assertion
{
    /**
     * $key.
     *
     * @var string
     */
    public $key = '';

    /**
     * $value.
     *
     * @var string
     */
    public $value = '';

    /**
     * $tokens.
     *
     * @var array
     */
    public $tokens = [];

    /**
     * $policy.
     *
     * @var array
     */
    public $policy = [];

    /**
     * $rM.
     *
     * @var RoleManager
     */
    public $rM;

    /**
     * @param RoleManager $rm
     *
     * @throws CasbinException
     */
    public function buildRoleLinks(RoleManager $rm)
    {
        $this->rM = $rm;
        $count = substr_count($this->value, '_');

        foreach ($this->policy as $rule) {
            if ($count < 2) {
                throw new CasbinException('the number of "_" in role definition should be at least 2');
            }
            if (\count($rule) < $count) {
                throw new CasbinException('grouping policy elements do not meet role definition');
            }

            if (2 == $count) {
                $this->rM->addLink($rule[0], $rule[1]);
            } elseif (3 == $count) {
                $this->rM->addLink($rule[0], $rule[1], $rule[2]);
            } elseif (4 == $count) {
                $this->rM->addLink($rule[0], $rule[1], $rule[2], $rule[3]);
            }
        }

        Log::logPrint('Role links for: '.$this->key);
        $this->rM->printRoles();
    }
}
