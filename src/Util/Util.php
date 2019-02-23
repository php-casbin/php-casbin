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
        if (0 === strpos($s, 'r.')) {
            $s = substr_replace($s, 'r_', 0, 2);
        }
        if (0 === strpos($s, 'p.')) {
            $s = substr_replace($s, 'p_', 0, 2);
        }

        $s = preg_replace_callback("~(\|| |=|\)|\(|&|<|>|,|\+|-|!|\*|\/)(r|p)(\.)~", function ($m) {
            return $m[1].$m[2].'_';
        }, $s);

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
