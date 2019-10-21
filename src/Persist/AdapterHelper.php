<?php

declare(strict_types=1);

namespace Casbin\Persist;

use Casbin\Model\Model;

/**
 * Trait AdapterHelper.
 *
 * @author techlee@qq.com
 */
trait AdapterHelper
{
    /**
     * @param string              $line
     * @param \Casbin\Model\Model $model
     */
    public function loadPolicyLine(string $line, Model $model): void
    {
        if ('' == $line) {
            return;
        }

        if ('#' == substr($line, 0, 1)) {
            return;
        }

        $tokens = explode(', ', $line);
        $key = $tokens[0];
        $sec = $key[0];

        if (!isset($model[$sec][$key])) {
            return;
        }

        $assertions = $model[$sec];
        $assertions[$key]->policy[] = \array_slice($tokens, 1);
        $model[$sec] = $assertions;
    }
}
