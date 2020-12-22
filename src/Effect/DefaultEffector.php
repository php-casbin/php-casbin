<?php

declare(strict_types=1);

namespace Casbin\Effect;

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
     * @param array $results
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function mergeEffects(string $expr, array $effects, array $results): bool
    {
        $result = false;
        if ('some(where (p_eft == allow))' == $expr) {
            if (in_array(self::ALLOW, $effects, true)) {
                $result = true;
            }
        } elseif ('!some(where (p_eft == deny))' == $expr) {
            $result = true;
            if (in_array(self::DENY, $effects, true)) {
                $result = false;
            }
        } elseif ('some(where (p_eft == allow)) && !some(where (p_eft == deny))' == $expr) {
            if (in_array(self::DENY, $effects, true)) {
                $result = false;
            } elseif (in_array(self::ALLOW, $effects, true)) {
                $result = true;
            }
        } elseif ('priority(p_eft) || deny' == $expr) {
            foreach ($effects as $eft) {
                if (self::INDETERMINATE != $eft) {
                    if (self::ALLOW == $eft) {
                        $result = true;
                    } else {
                        $result = false;
                    }

                    break;
                }
            }
        } else {
            throw new CasbinException('unsupported effect');
        }

        return $result;
    }
}
