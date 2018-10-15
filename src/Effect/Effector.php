<?php
namespace Casbin\Effect;

interface Effector
{
    public function mergeEffects($expr, $effects, $results);
}
