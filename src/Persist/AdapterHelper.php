<?php

namespace Casbin\Persist;

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
    public function loadPolicyLine($line, $model)
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

        if (!isset($model->model[$sec][$key])) {
            return;
        }
        $model->model[$sec][$key]->policy[] = \array_slice($tokens, 1);
    }
}
