<?php

namespace Casbin\Util;

/**
 * Util.
 *
 * @author techlee@qq.com
 */
class Util
{
    public static function escapeAssertion($s)
    {
        $s = str_replace('r.', 'r_', $s);
        $s = str_replace('p.', 'p_', $s);

        return $s;
    }

    public static function removeComments($s)
    {
        $pos = strpos($s, '#');

        return false === $pos ? $s : trim(substr($s, 0, $pos));
    }

    public static function arrayToString($s)
    {
        return implode(', ', $s);
    }

    public static function arrayRemoveDuplicates(&$s)
    {
        $found = [];
        $j = 0;
        foreach ($s as $i => $x) {
            if (!isset($found[$x])) {
                $found[$x] = true;
                $s[$j] = $s[$i];
                ++$j;
            }
        }
        $s = \array_slice($s, 0, $j);
    }
}
