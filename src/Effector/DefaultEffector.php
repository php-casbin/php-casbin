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
     * @param array $effects
     * @param array $matches
     * @param int $policyIndex
     * @param int $policyLength
     *
     * @return array
     *
     * @throws CasbinException
     */
    public function mergeEffects(string $expr, array $effects, array $matches, int $policyIndex, int $policyLength): array
    {
        $result = Effector::INDETERMINATE;
        $explainIndex = -1;

        switch ($expr) {
            case "some(where (p_eft == allow))":
                if ($matches[$policyIndex] == 0) {
                    break;
                }
                // only check the current policyIndex
                if ($effects[$policyIndex] === Effector::ALLOW) {
                    $result = Effector::ALLOW;
                    $explainIndex = $policyIndex;
                    break;
                }
                break;
            case "!some(where (p_eft == deny))":
                // only check the current policyIndex
                if ($matches[$policyIndex] != 0 && $effects[$policyIndex] === Effector::DENY) {
                    $result = Effector::DENY;
                    $explainIndex = $policyIndex;
                    break;
                }
                // if no deny rules are matched  at last, then allow
                if ($policyIndex == $policyLength - 1) {
                    $result = Effector::ALLOW;
                }
                break;
            case "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
                // short-circuit if matched deny rule
                if ($matches[$policyIndex] != 0 && $effects[$policyIndex] === Effector::DENY) {
                    $result = Effector::DENY;
                    // set hit rule to the (first) matched deny rule
                    $explainIndex = $policyIndex;
                    break;
                }

                // short-circuit some effects in the middle
                if ($policyIndex < $policyLength - 1) {
                    // choose not to short-circuit
                    return [$result, $explainIndex];
                }
                // merge all effects at last
                foreach ($effects as $i => $eft) {
                    if ($matches[$i] == 0) {
                        continue;
                    }

                    if ($eft === Effector::ALLOW) {
                        $result = Effector::ALLOW;
                        // set hit rule to first matched allow rule
                        $explainIndex = $i;
                        break;
                    }
                }
                break;
            case "priority(p_eft) || deny":
            case "subjectPriority(p_eft) || deny":
                // reverse merge, short-circuit may be earlier
                for ($i = count($effects) - 1; $i >= 0; $i--) {
                    if ($matches[$i] == 0) {
                        continue;
                    }

                    if ($effects[$i] != Effector::INDETERMINATE) {
                        if ($effects[$i] === Effector::ALLOW) {
                            $result = Effector::ALLOW;
                        } else {
                            $result = Effector::DENY;
                        }
                        $explainIndex = $i;
                        break;
                    }
                }
                break;
            default:
                throw new CasbinException('unsupported effect');
        }

        return [$result, $explainIndex];
    }
}
