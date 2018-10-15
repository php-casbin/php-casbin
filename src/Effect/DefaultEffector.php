<?php
namespace Casbin\Effect;

use Casbin\Exceptions\CasbinException;

class DefaultEffector implements Effector
{
    const ALLOW         = 0;
    const INDETERMINATE = 1;
    const DENY          = 2;

    public function mergeEffects($expr, $effects, $results)
    {
        $result = false;
        if ($expr == "some(where (p_eft == allow))") {
            foreach ($effects as $eft) {
                if ($eft == self::ALLOW) {
                    $result = true;
                    break;
                }
            }
        } elseif ($expr == "!some(where (p_eft == deny))") {
            $result = true;
            foreach ($effects as $eft) {
                if ($eft == self::DENY) {
                    $result = false;
                    break;
                }
            }
        } elseif ($expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))") {
            foreach ($effects as $eft) {
                if ($eft == self::ALLOW) {
                    $result = true;
                } elseif ($eft == self::DENY) {
                    $result = false;
                    break;
                }
            }
        } elseif ($expr == "priority(p_eft) || deny") {
            foreach ($effects as $eft) {
                if ($eft != self::INDETERMINATE) {
                    if ($eft == self::ALLOW) {
                        $result = true;
                    } else {
                        $result = false;
                    }
                    break;
                }

            }
        } else {
            throw new CasbinException("unsupported effect");
        }

        return $result;
    }
}
