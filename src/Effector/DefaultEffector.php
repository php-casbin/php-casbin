<?php

declare(strict_types=1);

namespace Casbin\Effector;

use Casbin\Exceptions\CasbinException;

/**
 * Class DefaultEffector.
 *
 * @author techlee@qq.com
 */
class DefaultEffector extends Effector
{
    /**
     * Merges all matching results collected by the enforcer into a single decision.
     *
     * @param string $expr
     * @param array  $effects
     * @param array  $matches
     * @param int    $policyIndex
     * @param int    $policyLength
     *
     * @return array
     *
     * @throws CasbinException
     */
    public function mergeEffects(string $expr, array $effects, array $matches, int $policyIndex, int $policyLength): array
    {
        $result = Effector::INDETERMINATE;
        $explainIndex = -1;

        // short-circuit some effects in the middle
        if ($expr != 'priority(p_eft) || deny' && $expr != 'subjectPriority(p_eft) || deny') {
            if ($policyIndex < $policyLength - 1) {
                // choose not to short-circuit
                return [$result, $explainIndex];
            }
        }

        // merge all effects at last
        if ($expr == 'some(where (p_eft == allow))') {
            $result = Effector::INDETERMINATE;
            foreach ($effects as $i => $eft) {
                if ($matches[$i] == 0) {
                    continue;
                }

                if ($eft == Effector::ALLOW) {
                    $result = Effector::ALLOW;
                    $explainIndex = $i;
                    break;
                }
            }
        } elseif ($expr == '!some(where (p_eft == deny))') {
            // if no deny rules are matched, then allow
            $result = Effector::ALLOW;
            foreach ($effects as $i => $eft) {
                if ($matches[$i] == 0) {
                    continue;
                }

                if ($eft == Effector::DENY) {
                    $result = Effector::DENY;
                    $explainIndex = $i;
                    break;
                }
            }
        } elseif ($expr == 'some(where (p_eft == allow)) && !some(where (p_eft == deny))') {
            $result = Effector::INDETERMINATE;
            foreach ($effects as $i => $eft) {
                if ($matches[$i] == 0) {
                    continue;
                }
    
                if ($eft == Effector::ALLOW) {
                    // set hit rule to first matched allow rule, maybe overridden by the deny part
                    if ($result == Effector::INDETERMINATE) {
                        $explainIndex = $i;
                    }
                    $result = Effector::ALLOW;
                } elseif ($eft == Effector::DENY) {
                    $result = Effector::DENY;
                    // set hit rule to the (first) matched deny rule
                    $explainIndex = $i;
                    break;
                }
            }
        } elseif ($expr == 'priority(p_eft) || deny' || $expr == 'subjectPriority(p_eft) || deny') {
            $result = Effector::INDETERMINATE;
            foreach ($effects as $i => $eft) {
                if ($matches[$i] == 0) {
                    continue;
                }
    
                if ($eft != Effector::INDETERMINATE) {
                    if ($eft == Effector::ALLOW) {
                        $result = Effector::ALLOW;
                    } else {
                        $result = Effector::DENY;
                    }
                    $explainIndex = $i;
                    break;
                }
            }
        } else {
            throw new CasbinException('unsupported effect');
        }

        return [$result, $explainIndex];
    }
}
