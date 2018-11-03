<?php

namespace Casbin\Persist;

/**
 * AdapterHelper.
 *
 * @author techlee@qq.com
 */
trait AdapterHelper
{
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
