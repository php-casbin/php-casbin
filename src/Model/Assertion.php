<?php
namespace Casbin\Model;

use Casbin\Exceptions\CasbinException;
use Casbin\Util\Log;

/**
 * Assertion
 * @author techlee@qq.com
 */
class Assertion
{
    public $key    = '';
    public $value  = '';
    public $tokens = [];
    public $policy = [];
    public $rM;

    public function buildRoleLinks($rm)
    {
        $this->rM = $rm;
        $count    = substr_count($this->value, '_');

        foreach ($this->policy as $rule) {
            if ($count < 2) {
                throw new CasbinException("the number of \"_\" in role definition should be at least 2");
            }
            if (count($rule) < $count) {
                throw new CasbinException("grouping policy elements do not meet role definition");
            }

            if ($count == 2) {
                $this->rM->addLink($rule[0], $rule[1]);
            } elseif ($count == 3) {
                $this->rM->addLink($rule[0], $rule[1], $rule[2]);
            } elseif ($count == 4) {
                $this->rM->addLink($rule[0], $rule[1], $rule[2], $rule[3]);
            }
        }

        Log::logPrint("Role links for: " . $this->key);
        $this->rM->printRoles();
    }
}
