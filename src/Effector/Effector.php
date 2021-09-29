<?php

declare(strict_types=1);

namespace Casbin\Effector;

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
     * @param string $expr
     * @param array  $effects
     * @param array  $matches
     * @param int    $policyIndex
     * @param int    $policyLength
     * 
     * @return array
     */
    abstract public function mergeEffects(string $expr, array $effects, array $matches, int $policyIndex, int $policyLength): array;
}
