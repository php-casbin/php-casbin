<?php

namespace Casbin\Effect;

/**
 * Class Effector.
 *
 * @author techlee@qq.com
 */
abstract class Effector
{
    const ALLOW = 0;

    const INDETERMINATE = 1;

    const DENY = 2;

    /**
     * @param $expr
     * @param array $effects
     * @param array $results
     *
     * @return mixed
     */
    abstract public function mergeEffects($expr, array $effects, array $results);
}
