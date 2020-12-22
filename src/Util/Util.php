<?php

declare(strict_types=1);

namespace Casbin\Util;

use Casbin\Exceptions\CasbinException;

/**
 * Class Util.
 *
 * @author techlee@qq.com
 */
class Util
{
    const REGEXP = '/\beval\((?P<rule>[^),]*)\)/';

    /**
     * Escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
     *
     * @param string $s
     *
     * @return string
     * @throws CasbinException
     */
    public static function escapeAssertion(string $s): string
    {
        if (0 === strpos($s, 'r.')) {
            $s = substr_replace($s, 'r_', 0, 2);
        }
        if (0 === strpos($s, 'p.')) {
            $s = substr_replace($s, 'p_', 0, 2);
        }

        $s = preg_replace_callback("~(\|| |=|\)|\(|&|<|>|,|\+|-|!|\*|\/)(r|p)(\.)~", function ($m) {
            return $m[1] . $m[2] . '_';
        }, $s);

        if (null === $s) {
            throw new CasbinException(sprintf('Unable to escape assertion "%s"', $s));
        }

        return $s;
    }

    /**
     *Removes the comments starting with # in the text.
     *
     * @param string $s
     *
     * @return string
     */
    public static function removeComments(string $s): string
    {
        $pos = strpos($s, '#');

        return false === $pos ? $s : trim(substr($s, 0, $pos));
    }

    /**
     * Gets a printable string for a string array.
     *
     * @param array $s
     *
     * @return string
     */
    public static function arrayToString(array $s): string
    {
        return implode(', ', $s);
    }

    /**
     * Removes any duplicated elements in a string array.
     *
     * @param array $s
     */
    public static function arrayRemoveDuplicates(array &$s): void
    {
        $s = array_keys(array_flip($s));
    }

    /**
     * Determine whether matcher contains function eval.
     *
     * @param string $s
     *
     * @return bool
     */
    public static function hasEval(string $s): bool
    {
        return (bool)preg_match(self::REGEXP, $s);
    }

    /**
     * Replace function eval with the value of its parameters.
     *
     * @param string $s
     * @param string $rule
     *
     * @return string
     */
    public static function replaceEval(string $s, string $rule): string
    {
        return (string)preg_replace(self::REGEXP, '(' . $rule . ')', $s);
    }

    /**
     * Returns the parameters of function eval.
     *
     * @param string $s
     *
     * @return array
     */
    public static function getEvalValue(string $s): array
    {
        preg_match_all(self::REGEXP, $s, $matches);

        return $matches['rule'];
    }
}
