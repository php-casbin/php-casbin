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
     * @return array
     *
     * @throws CasbinException
     */
    public function mergeEffects(string $expr, array $effects, array $results): array
    {
        $result = false;
        $explainIndex = -1;
        if ('some(where (p_eft == allow))' == $expr) {
            $explainIndex = array_search(self::ALLOW, $effects, true);
            if ($explainIndex !== false) {
                $result = true;
            }
        } elseif ('!some(where (p_eft == deny))' == $expr) {
            $result = true;
            $explainIndex = array_search(self::DENY, $effects, true);
            if ($explainIndex !== false) {
                $result = false;
            }
        } elseif ('some(where (p_eft == allow)) && !some(where (p_eft == deny))' == $expr) {
            $result = false;
            foreach ($effects as $i => $eft) {
                if ($eft === self::ALLOW) {
                    $result = true;
                } elseif ($eft === self::DENY) {
                    $result = false;
                    $explainIndex = $i;
                    break;
                }
            }
        } elseif ('priority(p_eft) || deny' == $expr) {
            $explain = array_filter($effects, function ($val) {
                return $val != self::INDETERMINATE;
            });
            $explainIndex = $explain ? array_key_first($explain) : false;
            if ($explainIndex !== false) {
                if (self::ALLOW == $explain[$explainIndex]) {
                    $result = true;
                } else {
                    $result = false;
                }
            }
        } else {
            throw new CasbinException('unsupported effect');
        }
        $explainIndex = $explainIndex === false ? -1 : $explainIndex;
        return [$result, $explainIndex];
    }
}
