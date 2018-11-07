<?php

namespace Casbin\Effect;

/**
 * Effector.
 *
 * @author techlee@qq.com
 */
abstract class Effector
{
    const ALLOW = 0;

    const INDETERMINATE = 1;

    const DENY = 2;

    abstract public function mergeEffects($expr, array $effects, array $results);
}
