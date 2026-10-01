<?php

declare(strict_types=1);

namespace Casbin\Util;

use Casbin\Exceptions\BadPatternException;

/**
 * Glob matcher supporting `**` path-segment wildcards.
 *
 * A `**` used as a full path segment matches zero or more path segments,
 * while a `**` inside a segment behaves like `*`. Within a segment, `*` and
 * `?` never match `/`, `[...]` character classes and `\` escapes are
 * supported, and `{alt1,alt2}` brace alternates expand as in brace
 * expansion. A trailing `**` — with or without slashes around it — can also
 * match a zero-length remainder.
 *
 * Malformed syntax the matcher actually reaches - an unterminated `[` class,
 * a dangling `\` escape, an unclosed `{` - never matches. Malformed parts
 * the matcher never reaches do not affect the result: once an earlier brace
 * alternative has matched, later alternatives are not evaluated, so
 * `{ok,[}` still matches `ok`.
 *
 * Brace expansion restarts segment tracking, so a `**` that lands at the
 * start of an expanded alternative spans path segments even when the brace
 * itself sat mid-segment; and a `,` or `}` inside a `[...]` class is still
 * treated as a brace-alternation delimiter. Both are covered by regression
 * tests.
 */
final class DoubleStar
{
    private const MAX_RUNE = 0x10FFFF;
    private const BACKSLASH = 0x5C;
    private const DASH = 0x2D;

    /**
     * Determines whether $value matches the given glob $pattern.
     *
     * @param string $pattern
     * @param string $value
     *
     * @return bool
     */
    public static function match(string $pattern, string $value): bool
    {
        try {
            return self::doMatchWithSeparator($pattern, $value, 0x2F, true, -1, -1, -1, -1, 0, 0);
        } catch (BadPatternException) {
            // malformed pattern - report no match
            return false;
        }
    }

    /**
     * The main match loop. All
     * mutable state (indices, segment position and backtracking positions) is
     * advanced in place; the per-byte handling lives in the matchXxx helpers
     * and rewinding in backtrack().
     *
     * @param string $pattern
     * @param string $name
     * @param int $separator
     * @param bool $validate
     * @param int $starStarPatternBacktrack
     * @param int $starStarNameBacktrack
     * @param int $starPatternBacktrack
     * @param int $starNameBacktrack
     * @param int $patIdx
     * @param int $nameIdx
     *
     * @return bool
     */
    private static function doMatchWithSeparator(string $pattern, string $name, int $separator, bool $validate, int $starStarPatternBacktrack, int $starStarNameBacktrack, int $starPatternBacktrack, int $starNameBacktrack, int $patIdx, int $nameIdx): bool
    {
        $patLen = strlen($pattern);
        $nameLen = strlen($name);
        $startOfSegment = true;

        while ($nameIdx < $nameLen) {
            if ($patIdx < $patLen) {
                $byte = $pattern[$patIdx];

                if ('*' === $byte) {
                    if (self::matchStarSequence($pattern, $name, $separator, $patIdx, $nameIdx, $startOfSegment, $starPatternBacktrack, $starNameBacktrack, $starStarPatternBacktrack, $starStarNameBacktrack)) {
                        // pattern ends in `/**`: match any remaining input
                        return true;
                    }
                    continue;
                }

                if ('?' === $byte) {
                    $startOfSegment = false;
                    [$nameRune, $nameRuneLen] = self::decodeRune($name, $nameIdx);
                    if ($nameRune !== $separator) {
                        // `?` cannot match the separator
                        $patIdx++;
                        $nameIdx += $nameRuneLen;
                        continue;
                    }
                } elseif ('[' === $byte) {
                    $startOfSegment = false;
                    if (self::matchCharacterClass($pattern, $name, $separator, $patIdx, $nameIdx)) {
                        continue;
                    }
                    // class did not match - fall through to the backtracking section
                } elseif ('{' === $byte) {
                    $startOfSegment = false;

                    return self::matchBraceAlternates($pattern, $name, $separator, $validate, $starStarPatternBacktrack, $starStarNameBacktrack, $starPatternBacktrack, $starNameBacktrack, $patIdx, $nameIdx);
                } else {
                    if (self::matchLiteralRune($pattern, $name, $separator, $patIdx, $nameIdx, $startOfSegment)) {
                        continue;
                    }
                    // literal mismatch - fall through to the backtracking section
                }
            }

            if (!self::backtrack($pattern, $name, $nameLen, $separator, $validate, $patIdx, $nameIdx, $startOfSegment, $starPatternBacktrack, $starNameBacktrack, $starStarPatternBacktrack, $starStarNameBacktrack)) {
                return false;
            }
        }

        if ($nameIdx < $nameLen) {
            // we reached the end of `pattern` before the end of `name`
            return false;
        }

        // we've reached the end of `name`; we've successfully matched if we've
        // also reached the end of `pattern`, or if the rest of `pattern` can
        // match a zero-length string
        return self::isZeroLengthPattern(substr($pattern, $patIdx), $separator);
    }

    /**
     * Consumes a `*` or `**` sequence at $patIdx, recording the backtracking
     * positions.
     *
     * Returns true when the pattern ends with a full-segment `**` that
     * matches any remaining input, in which case the caller can report a
     * match immediately; false when matching continues.
     *
     * @param string $pattern
     * @param string $name
     * @param int $separator
     * @param int $patIdx
     * @param int $nameIdx
     * @param bool $startOfSegment
     * @param int $starPatternBacktrack
     * @param int $starNameBacktrack
     * @param int $starStarPatternBacktrack
     * @param int $starStarNameBacktrack
     *
     * @return bool
     */
    private static function matchStarSequence(string $pattern, string $name, int $separator, int &$patIdx, int $nameIdx, bool &$startOfSegment, int &$starPatternBacktrack, int &$starNameBacktrack, int &$starStarPatternBacktrack, int &$starStarNameBacktrack): bool
    {
        $patLen = strlen($pattern);
        $patIdx++;
        if ($patIdx < $patLen && '*' === $pattern[$patIdx]) {
            // a full-segment `**` must begin with a path separator, otherwise
            // we'll treat it like a single star
            $patIdx++;
            if ($startOfSegment) {
                if ($patIdx >= $patLen) {
                    // pattern ends in `/**`: match any remaining input
                    return true;
                }

                // a full-segment `**` must also end with a path separator,
                // otherwise we're just going to treat it like a single star
                [$patRune, $patRuneLen] = self::decodeRune($pattern, $patIdx);
                if ($patRune === $separator) {
                    $patIdx += $patRuneLen;

                    $starStarPatternBacktrack = $patIdx;
                    $starStarNameBacktrack = $nameIdx;
                    $starPatternBacktrack = -1;
                    $starNameBacktrack = -1;

                    return false;
                }
            }
        }

        $startOfSegment = false;
        $starPatternBacktrack = $patIdx;
        $starNameBacktrack = $nameIdx;

        return false;
    }

    /**
     * Matches a `[...]` character class at $patIdx against the rune at
     * $nameIdx.
     *
     * Returns true when the class matched and both indices were advanced past
     * it, false when the class did not match ($patIdx is left where scanning
     * stopped so the caller can backtrack). Throws BadPatternException when
     * the class is malformed.
     *
     * @param string $pattern
     * @param string $name
     * @param int $separator
     * @param int $patIdx
     * @param int $nameIdx
     *
     * @return bool
     */
    private static function matchCharacterClass(string $pattern, string $name, int $separator, int &$patIdx, int &$nameIdx): bool
    {
        $patLen = strlen($pattern);
        $patIdx++; // skip `[`
        if ($patIdx >= $patLen) {
            // class didn't end
            throw new BadPatternException('unterminated character class');
        }
        [$nameRune, $nameRuneLen] = self::decodeRune($name, $nameIdx);

        $matched = false;
        $negate = '!' === $pattern[$patIdx] || '^' === $pattern[$patIdx];
        if ($negate) {
            $patIdx++;
        }

        if ($patIdx >= $patLen || ']' === $pattern[$patIdx]) {
            // class didn't end or empty character class
            throw new BadPatternException('unterminated character class');
        }

        $last = self::MAX_RUNE;
        for (; $patIdx < $patLen && ']' !== $pattern[$patIdx];) {
            [$patRune, $patRuneLen] = self::decodeRune($pattern, $patIdx);
            $patIdx += $patRuneLen;

            // match a range
            if ($last < self::MAX_RUNE && self::DASH === $patRune && $patIdx < $patLen && ']' !== $pattern[$patIdx]) {
                if ('\\' === $pattern[$patIdx]) {
                    // next character is escaped
                    $patIdx++;
                }
                [$patRune, $patRuneLen] = self::decodeRune($pattern, $patIdx);
                $patIdx += $patRuneLen;

                if ($last <= $nameRune && $nameRune <= $patRune) {
                    $matched = true;
                    break;
                }

                // didn't match range - reset `last`
                $last = self::MAX_RUNE;
                continue;
            }

            // not a range - check if the next rune is escaped
            if (self::BACKSLASH === $patRune) {
                [$patRune, $patRuneLen] = self::decodeRune($pattern, $patIdx);
                $patIdx += $patRuneLen;
            }

            // check if the rune matches
            if ($patRune === $nameRune) {
                $matched = true;
                break;
            }

            // no matches yet
            $last = $patRune;
        }

        if ($matched === $negate) {
            // failed to match - if we reached the end of the pattern, that
            // means we never found a closing `]`
            if ($patIdx >= $patLen) {
                throw new BadPatternException('unterminated character class');
            }

            return false;
        }

        $closingIdx = self::indexUnescapedByte($pattern, ']', $patIdx, $separator !== '\\');
        if (-1 === $closingIdx) {
            // no closing `]`
            throw new BadPatternException('unterminated character class');
        }

        $patIdx = $closingIdx + 1;
        $nameIdx += $nameRuneLen;

        return true;
    }

    /**
     * Matches a `{alt1,alt2,...}` brace alternation at $patIdx by expanding it
     * in place and recursing on each alternative.
     *
     * @param string $pattern
     * @param string $name
     * @param int $separator
     * @param bool $validate
     * @param int $starStarPatternBacktrack
     * @param int $starStarNameBacktrack
     * @param int $starPatternBacktrack
     * @param int $starNameBacktrack
     * @param int $patIdx
     * @param int $nameIdx
     *
     * @return bool
     */
    private static function matchBraceAlternates(string $pattern, string $name, int $separator, bool $validate, int $starStarPatternBacktrack, int $starStarNameBacktrack, int $starPatternBacktrack, int $starNameBacktrack, int $patIdx, int $nameIdx): bool
    {
        $beforeIdx = $patIdx;
        $patIdx++;
        $closingIdx = self::indexMatchedClosingAlt($pattern, $patIdx, $separator !== '\\');
        if (-1 === $closingIdx) {
            // no closing `}`
            return false;
        }

        for (;;) {
            $commaIdx = self::indexNextAlt($pattern, $patIdx, $closingIdx, $separator !== '\\');
            if (-1 === $commaIdx) {
                break;
            }

            $expanded = substr($pattern, 0, $beforeIdx) . substr($pattern, $patIdx, $commaIdx - $patIdx) . substr($pattern, $closingIdx + 1);
            if (self::doMatchWithSeparator($expanded, $name, $separator, $validate, $starStarPatternBacktrack, $starStarNameBacktrack, $starPatternBacktrack, $starNameBacktrack, $beforeIdx, $nameIdx)) {
                return true;
            }

            $patIdx = $commaIdx + 1;
        }

        $expanded = substr($pattern, 0, $beforeIdx) . substr($pattern, $patIdx, $closingIdx - $patIdx) . substr($pattern, $closingIdx + 1);

        return self::doMatchWithSeparator($expanded, $name, $separator, $validate, $starStarPatternBacktrack, $starStarNameBacktrack, $starPatternBacktrack, $starNameBacktrack, $beforeIdx, $nameIdx);
    }

    /**
     * Compares the literal rune at $patIdx (honoring a leading backslash
     * escape) with the rune at $nameIdx.
     *
     * Returns true when both runes matched and the indices were advanced,
     * false on mismatch ($patIdx is moved back onto the backslash first when
     * the rune was escaped, so the caller can backtrack). Throws
     * BadPatternException when the escape is dangling.
     *
     * @param string $pattern
     * @param string $name
     * @param int $separator
     * @param int $patIdx
     * @param int $nameIdx
     * @param bool $startOfSegment
     *
     * @return bool
     */
    private static function matchLiteralRune(string $pattern, string $name, int $separator, int &$patIdx, int &$nameIdx, bool &$startOfSegment): bool
    {
        $patLen = strlen($pattern);
        if ('\\' === $pattern[$patIdx] && $separator !== '\\') {
            // next rune is "escaped" in the pattern - literal match
            $patIdx++;
            if ($patIdx >= $patLen) {
                // pattern ended
                throw new BadPatternException('dangling escape');
            }
        }

        [$patRune, $patRuneLen] = self::decodeRune($pattern, $patIdx);
        [$nameRune, $nameRuneLen] = self::decodeRune($name, $nameIdx);
        if ($patRune !== $nameRune) {
            if ($separator !== '\\' && $patIdx > 0 && '\\' === $pattern[$patIdx - 1]) {
                // if this rune was meant to be escaped, we need to move patIdx
                // back to the backslash before backtracking or validating below
                $patIdx--;
            }

            return false;
        }

        $patIdx += $patRuneLen;
        $nameIdx += $nameRuneLen;
        $startOfSegment = $patRune === $separator;

        return true;
    }

    /**
     * Applies the `*` and `**` backtracking positions.
     *
     * Returns true when the match loop should continue with rewound indices,
     * or false when no backtracking option is left (the caller reports no
     * match). Throws BadPatternException when the remaining pattern tail is
     * malformed.
     *
     * @param string $pattern
     * @param string $name
     * @param int $nameLen
     * @param int $separator
     * @param bool $validate
     * @param int $patIdx
     * @param int $nameIdx
     * @param bool $startOfSegment
     * @param int $starPatternBacktrack
     * @param int $starNameBacktrack
     * @param int $starStarPatternBacktrack
     * @param int $starStarNameBacktrack
     *
     * @return bool
     */
    private static function backtrack(string $pattern, string $name, int $nameLen, int $separator, bool $validate, int &$patIdx, int &$nameIdx, bool &$startOfSegment, int &$starPatternBacktrack, int &$starNameBacktrack, int &$starStarPatternBacktrack, int &$starStarNameBacktrack): bool
    {
        if ($starPatternBacktrack >= 0) {
            // `*` backtrack, but only if the `name` rune isn't the separator
            [$nameRune, $nameRuneLen] = self::decodeRune($name, $starNameBacktrack);
            if ($nameRune !== $separator) {
                $starNameBacktrack += $nameRuneLen;
                $patIdx = $starPatternBacktrack;
                $nameIdx = $starNameBacktrack;
                $startOfSegment = false;

                return true;
            }
        }

        if ($starStarPatternBacktrack >= 0) {
            // `**` backtrack, advance `name` past next separator
            $nameIdx = $starStarNameBacktrack;
            while ($nameIdx < $nameLen) {
                [$nameRune, $nameRuneLen] = self::decodeRune($name, $nameIdx);
                $nameIdx += $nameRuneLen;
                if ($nameRune === $separator) {
                    $starStarNameBacktrack = $nameIdx;
                    $patIdx = $starStarPatternBacktrack;
                    $startOfSegment = true;

                    return true;
                }
            }
        }

        if ($validate && $patIdx < strlen($pattern) && !self::doValidatePattern(substr($pattern, $patIdx), $separator)) {
            throw new BadPatternException('malformed pattern');
        }

        return false;
    }

    /**
     * Reports whether the remaining pattern can match a zero-length string.
     *
     * @param string $pattern
     * @param int $separator
     *
     * @return bool
     */
    private static function isZeroLengthPattern(string $pattern, int $separator): bool
    {
        // `/**`, `**/`, and `/**/` are special cases - a pattern such as
        // `path/to/a/**` or `path/to/a/**/` should match `path/to/a` because
        // `a` might be a directory
        if ('' === $pattern
            || '*' === $pattern
            || '**' === $pattern
            || self::runeChar($separator) . '**' === $pattern
            || '**' . self::runeChar($separator) === $pattern
            || self::runeChar($separator) . '**' . self::runeChar($separator) === $pattern) {
            return true;
        }

        if ('{' === $pattern[0]) {
            $closingIdx = self::indexMatchedClosingAlt($pattern, 1, $separator !== '\\');
            if (-1 === $closingIdx) {
                // no closing '}'
                throw new BadPatternException('unterminated brace alternation');
            }

            $patIdx = 1;
            for (;;) {
                $commaIdx = self::indexNextAlt($pattern, $patIdx, $closingIdx, $separator !== '\\');
                if (-1 === $commaIdx) {
                    break;
                }

                if (self::isZeroLengthPattern(substr($pattern, $patIdx, $commaIdx - $patIdx) . substr($pattern, $closingIdx + 1), $separator)) {
                    return true;
                }

                $patIdx = $commaIdx + 1;
            }

            return self::isZeroLengthPattern(substr($pattern, $patIdx, $closingIdx - $patIdx) . substr($pattern, $closingIdx + 1), $separator);
        }

        // no luck - validate the rest of the pattern
        if (!self::doValidatePattern($pattern, $separator)) {
            throw new BadPatternException('malformed pattern');
        }

        return false;
    }

    /**
     * Validates pattern syntax: unterminated classes, stray braces and
     * dangling escapes are invalid.
     *
     * @param string $s
     * @param int $separator
     *
     * @return bool
     */
    private static function doValidatePattern(string $s, int $separator): bool
    {
        $altDepth = 0;
        $length = strlen($s);
        $i = 0;
        for (; $i < $length; $i++) {
            $byte = $s[$i];
            if ('\\' === $byte) {
                if ($separator !== '\\') {
                    // skip the next byte - invalid if there is no next byte
                    $i++;
                    if ($i >= $length) {
                        return false;
                    }
                }
            } elseif ('[' === $byte) {
                $i++;
                if ($i >= $length) {
                    // class didn't end
                    return false;
                }
                if ('^' === $s[$i] || '!' === $s[$i]) {
                    $i++;
                }
                if ($i >= $length || ']' === $s[$i]) {
                    // class didn't end or empty character class
                    return false;
                }

                for (; $i < $length; $i++) {
                    if ($separator !== '\\' && '\\' === $s[$i]) {
                        $i++;
                    } elseif (']' === $s[$i]) {
                        // looks good
                        continue 2;
                    }
                }

                // class didn't end
                return false;
            } elseif ('{' === $byte) {
                $altDepth++;
            } elseif ('}' === $byte) {
                if (0 === $altDepth) {
                    // alt end without a corresponding start
                    return false;
                }
                $altDepth--;
            }
        }

        // valid as long as all alts are closed
        return 0 === $altDepth;
    }

    /**
     * Finds the index of the first unescaped byte `$c` in `$s` at or after
     * `$start`, or -1.
     *
     * @param string $s
     * @param string $c
     * @param int $start
     * @param bool $allowEscaping
     *
     * @return int
     */
    private static function indexUnescapedByte(string $s, string $c, int $start, bool $allowEscaping): int
    {
        $length = strlen($s);
        for ($i = $start; $i < $length; $i++) {
            if ($allowEscaping && '\\' === $s[$i]) {
                // skip next byte
                $i++;
            } elseif ($s[$i] === $c) {
                return $i;
            }
        }

        return -1;
    }

    /**
     * Assuming the byte before `$start` is an opening `{`, finds the index of
     * the matching `}` in `$s`, skipping nested `{}` and accounting for
     * escaping, or -1.
     *
     * @param string $s
     * @param int $start
     * @param bool $allowEscaping
     *
     * @return int
     */
    private static function indexMatchedClosingAlt(string $s, int $start, bool $allowEscaping): int
    {
        $alts = 1;
        $length = strlen($s);
        for ($i = $start; $i < $length; $i++) {
            if ($allowEscaping && '\\' === $s[$i]) {
                // skip next byte
                $i++;
            } elseif ('{' === $s[$i]) {
                $alts++;
            } elseif ('}' === $s[$i]) {
                if (0 === --$alts) {
                    return $i;
                }
            }
        }

        return -1;
    }

    /**
     * Finds the index of the next unescaped comma at the outermost alternate
     * level within [$start, $end), or -1.
     *
     * @param string $s
     * @param int $start
     * @param int $end
     * @param bool $allowEscaping
     *
     * @return int
     */
    private static function indexNextAlt(string $s, int $start, int $end, bool $allowEscaping): int
    {
        $alts = 1;
        for ($i = $start; $i < $end; $i++) {
            if ($allowEscaping && '\\' === $s[$i]) {
                // skip next byte
                $i++;
            } elseif ('{' === $s[$i]) {
                $alts++;
            } elseif ('}' === $s[$i]) {
                $alts--;
            } elseif (',' === $s[$i] && 1 === $alts) {
                return $i;
            }
        }

        return -1;
    }

    /**
     * Decodes the UTF-8 rune at byte position $i, returning its code point and
     * byte width. Overlong encodings, surrogate halves and encodings beyond
     * U+10FFFF are rejected, so invalid or truncated sequences decode as
     * U+FFFD with width 1; positions at or past the end of the string decode
     * as an error rune with width 0.
     *
     * @param string $s
     * @param int $i
     *
     * @return array{int, int}
     */
    private static function decodeRune(string $s, int $i): array
    {
        $length = strlen($s);
        if ($i >= $length) {
            return [0xFFFD, 0];
        }

        $byte = ord($s[$i]);
        if ($byte < 0x80) {
            return [$byte, 1];
        }

        // Accepted lead byte ranges: 0xC2-0xDF (2 bytes),
        // 0xE0-0xEF (3 bytes), 0xF0-0xF4 (4 bytes); anything else - including
        // 0xC0/0xC1, which can only encode overlong 2-byte sequences - and
        // every invalid or truncated sequence decode as U+FFFD with width 1.
        if ($byte < 0xC2 || $byte > 0xF4) {
            return [0xFFFD, 1];
        }
        $width = $byte < 0xE0 ? 2 : ($byte < 0xF0 ? 3 : 4);
        if ($i + $width > $length) {
            return [0xFFFD, 1];
        }

        // The second byte is range-constrained per lead byte to reject
        // overlong encodings (E0, F0), surrogate halves (ED) and values above
        // U+10FFFF (F4); later bytes must be continuation bytes.
        $second = ord($s[$i + 1]);
        $secondLow = 0x80;
        if (0xE0 === $byte) {
            $secondLow = 0xA0;
        } elseif (0xED === $byte) {
            $secondLow = 0x80;
            if ($second >= 0xA0) {
                return [0xFFFD, 1];
            }
        } elseif (0xF0 === $byte) {
            $secondLow = 0x90;
        } elseif (0xF4 === $byte && $second >= 0x90) {
            return [0xFFFD, 1];
        }
        if ($second < $secondLow || $second > 0xBF) {
            return [0xFFFD, 1];
        }
        for ($j = 2; $j < $width; $j++) {
            if ((ord($s[$i + $j]) & 0xC0) !== 0x80) {
                return [0xFFFD, 1];
            }
        }

        $rune = $byte & (0x7F >> $width);
        for ($j = 1; $j < $width; $j++) {
            $rune = ($rune << 6) | (ord($s[$i + $j]) & 0x3F);
        }

        return [$rune, $width];
    }

    /**
     * Returns the UTF-8 encoding of a code point (only used for the
     * separator, which is ASCII in practice).
     *
     * @param int $rune
     *
     * @return string
     */
    private static function runeChar(int $rune): string
    {
        return $rune < 0x80 ? chr($rune) : '';
    }
}
