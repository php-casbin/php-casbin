<?php

namespace Casbin\Effect;

use Casbin\Exceptions\CasbinException;

/**
 * DefaultEffector.
 *
 * @author techlee@qq.com
 */
class DefaultEffector extends Effector
{
    /**
     * merges all matching results collected by the enforcer into a single decision.
     *
     * @param string $expr
     * @param array  $effects
     * @param array  $results
     *
     * @return bool
     */
    public function mergeEffects($expr, array $effects, array $results)
    {
        $result = false;
        if ('some(where (p_eft == allow))' == $expr) {
            foreach ($effects as $eft) {
                if (self::ALLOW == $eft) {
                    $result = true;

                    break;
                }
            }
        } elseif ('!some(where (p_eft == deny))' == $expr) {
            $result = true;
            foreach ($effects as $eft) {
                if (self::DENY == $eft) {
                    $result = false;

                    break;
                }
            }
        } elseif ('some(where (p_eft == allow)) && !some(where (p_eft == deny))' == $expr) {
            foreach ($effects as $eft) {
                if (self::ALLOW == $eft) {
                    $result = true;
                } elseif (self::DENY == $eft) {
                    $result = false;

                    break;
                }
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
