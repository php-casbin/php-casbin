<?php

declare(strict_types=1);

namespace Casbin\Util;

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
     * Quoted string literals are kept as they are.
     *
     * @param string $s
     *
     * @return string
     */
    public static function escapeAssertion(string $s): string
    {
        $result = '';
        $start = 0;
        $length = strlen($s);
        while ($start < $length) {
            // Jump to the next quote at C speed; a string without literals exits after one jump.
            $pos = $start + strcspn($s, '"\'', $start);
            if ($pos >= $length) {
                break;
            }
            if ($pos > $start) {
                $result .= self::escapeAssertionUnquoted(substr($s, $start, $pos - $start));
            }
            // Find the end of the string literal, honoring backslash escapes.
            $quote = $s[$pos];
            $end = $pos + 1;
            while ($end < $length) {
                $end += strcspn($s, $quote . '\\', $end);
                if ($end >= $length || $s[$end] === $quote) {
                    break;
                }
                $end += 2;
            }
            $end = $end < $length ? $end + 1 : $length;
            $result .= substr($s, $pos, $end - $pos);
            $start = $end;
        }

        if ($start < $length) {
            $result .= self::escapeAssertionUnquoted(substr($s, $start));
        }

        return $result;
    }

    /**
     * Escapes the dots of r./p. references outside of quoted literals.
     *
     * @param string $s
     *
     * @return string
     */
    private static function escapeAssertionUnquoted(string $s): string
    {
        $ss = preg_replace(
            "~(\|| |=|\)|\(|&|<|>|,|\+|-|!|\*|\/|^)((r|p)[0-9]*)(\.)~",
            '$1$2_',
            $s
        );

        return is_string($ss) ? $ss : $s;
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

    /**
     * ReplaceEvalWithMap replace function eval with the value of its parameters via given sets.
     *
     * @param string $src
     * @param array $sets
     * @return string|null
     */
    public static function replaceEvalWithMap(string $src, array $sets): ?string
    {
        return preg_replace_callback(self::REGEXP, function ($matches) use ($sets): string {
            $key = $matches['rule'];
    
            if (isset($sets[$key])) {
                $value = $sets[$key];
                return '(' . $value . ')';
            }
    
            return $matches[0];
        }, $src);
    }

    /**
     * Remove duplicate elements from an array.
     *
     * @param array $s
     * @return array
     */
    public static function removeDumplicateElement(array $s): array
    {
        return array_unique($s);
    }

    /**
     * Check if two arrays are equal, order-insensitive.
     *
     * @param array $a
     * @param array $b
     *
     * @return bool
     */
    public static function setEquals(array $a, array $b): bool
    {
        if (count($a) !== count($b)) {
            return false;
        }

        sort($a);
        sort($b);
        return $a == $b;
    }

    /**
     * Determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
     *
     * @param string $ipAddress
     * @param string $cidrAddress
     *
     * @return bool
     */
    public static function ipInSubnet(string $ipAddress, string $cidrAddress): bool
    {
        if (!str_contains($cidrAddress, '/')) {
            return $ipAddress === $cidrAddress;
        }

        [$subnet, $prefixLength] = explode('/', $cidrAddress);
        $prefixLength = intval($prefixLength);
        // IPv6
        if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {

            $ip = inet_pton($ipAddress);
            $subnet = inet_pton($subnet);

            if ($ip === false || $subnet === false) {
                return false;
            }

            $mask = str_repeat("f", intdiv($prefixLength, 4));
            $mask .= ['', '8', 'c', 'e'][$prefixLength % 4];
            $mask = str_pad($mask, 32, '0');
            $mask = pack("H*", $mask);

            return ($ip & $mask) === ($subnet & $mask);
        }
        // IPv4
        if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {

            $ip = ip2long($ipAddress);
            $subnet = ip2long($subnet);
            $mask = 0xffffffff << (32 - $prefixLength);

            return ($ip & $mask) === ($subnet & $mask);
        }

        return false;
    }
}
