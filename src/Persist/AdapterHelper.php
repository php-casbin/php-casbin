<?php

declare(strict_types=1);

namespace Casbin\Persist;

use Casbin\Model\Assertion;
use Casbin\Model\Model;
use Casbin\Model\Policy;

/**
 * Trait AdapterHelper.
 *
 * @author techlee@qq.com
 */
trait AdapterHelper
{
    /**
     * Loads a text line as a policy rule to model.
     *
     * @param string $line
     * @param Model $model
     */
    public function loadPolicyLine(string $line, Model $model): void
    {
        if ('' == $line) {
            return;
        }

        if ('#' == substr($line, 0, 1)) {
            return;
        }

        $tokens = array_map("trim", str_getcsv($line));

        $this->loadPolicyArray($tokens, $model);
    }

    /**
     * Loads a policy rule to model.
     *
     * @param array $rule
     * @param Model $model
     */
    public function loadPolicyArray(array $rule, Model $model): void
    {
        $key = $rule[0];
        $sec = $key[0];

        if (!isset($model[$sec][$key])) {
            return;
        }

        $assertions = $model[$sec];
        $assertion = $assertions[$key];
        if (!($assertion instanceof Assertion)) {
            return;
        }

        $rule = \array_slice($rule, 1);
        $assertion->policy[] = $rule;
        $assertion->policyMap[implode(Policy::DEFAULT_SEP, $rule)] = count($assertion->policy) - 1;

        $assertions[$key] = $assertion;
        $model[$sec] = $assertions;
    }
}
