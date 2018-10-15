<?php
namespace Casbin\Effect;

/**
 * Effector
 * @author techlee@qq.com
 */
interface Effector
{
    public function mergeEffects($expr, $effects, $results);
}
