<?php

namespace Casbin\Tests\Unit\Util;

use Casbin\Util\DoubleStar;
use PHPUnit\Framework\TestCase;

/**
 * DoubleStarTest.
 */
class DoubleStarTest extends TestCase
{
    /**
     * @dataProvider globMatchCasesProvider
     */
    public function testGlobMatch(string $value, string $pattern, bool $expected)
    {
        $this->assertSame($expected, DoubleStar::match($pattern, $value));
    }

    public function testEscapedSeparator()
    {
        // An escaped slash matches a literal `/` in the value.
        $this->assertTrue(DoubleStar::match('foo\/bar', 'foo/bar'));
        $this->assertTrue(DoubleStar::match('a\/b\/c', 'a/b/c'));
        $this->assertFalse(DoubleStar::match('foo\/bar', 'fooXbar'));
        $this->assertFalse(DoubleStar::match('foo\/bar', 'foo'));

        // After a matched (escaped) slash the position counts as the start of a
        // segment, so a following `**` spans any remainder.
        $this->assertTrue(DoubleStar::match('foo\/**', 'foo/x'));
        $this->assertTrue(DoubleStar::match('foo\/**', 'foo/x/y'));
    }

    public function testTrailingSlashDoublestar()
    {
        // A trailing `/**/` can match a zero-length remainder.
        $this->assertTrue(DoubleStar::match('a/**/', 'a'));
        $this->assertTrue(DoubleStar::match('a/**/', 'a/'));
        $this->assertTrue(DoubleStar::match('a/**/', 'a/b/'));
        $this->assertFalse(DoubleStar::match('a/**/', 'a/b'));
        $this->assertFalse(DoubleStar::match('a/**/', 'a/b/c'));
    }

    public function testCharacterClassWithEscapedSlash()
    {
        // An escaped slash inside a character class is a class member, not a
        // path boundary.
        $this->assertTrue(DoubleStar::match('foo[!\/]bar', 'fooXbar'));
        $this->assertFalse(DoubleStar::match('foo[!\/]bar', 'foo/bar'));
        $this->assertTrue(DoubleStar::match('foo[\/]bar', 'foo/bar'));
        $this->assertFalse(DoubleStar::match('foo[\/]bar', 'fooXbar'));
        $this->assertTrue(DoubleStar::match('foo[a\/]bar', 'fooabar'));
        $this->assertTrue(DoubleStar::match('foo[a\/]bar', 'foo/bar'));
        $this->assertFalse(DoubleStar::match('foo[a\/]bar', 'fooXbar'));
        // a class offering a slash among its alternatives can consume the
        // value's path boundary
        $this->assertTrue(DoubleStar::match('foo[X\/]bar', 'fooXbar'));
        $this->assertTrue(DoubleStar::match('foo[X\/]bar', 'foo/bar'));
    }

    public function testMultipleDoublestarSegments()
    {
        // Patterns with several full-segment `**` are evaluated in linear
        // backtracking passes and must not blow up combinatorially.
        $pattern = implode('/**/', array_fill(0, 10, 'y')) . '/z';
        $value = implode('/', array_fill(0, 24, 'y'));
        $this->assertFalse(DoubleStar::match($pattern, $value));
    }

    public function testBraceAlternates()
    {
        $this->assertTrue(DoubleStar::match('{a,b}x', 'bx'));
        $this->assertTrue(DoubleStar::match('{a,b}x', 'ax'));
        $this->assertFalse(DoubleStar::match('{a,b}x', 'cx'));
        $this->assertTrue(DoubleStar::match('{a,{b,c}}', 'b'));
        $this->assertTrue(DoubleStar::match('{a,{b,c}}', 'c'));
        $this->assertTrue(DoubleStar::match('foo{bar,baz}', 'foobar'));
        $this->assertTrue(DoubleStar::match('foo{bar,baz}', 'foobaz'));
        $this->assertTrue(DoubleStar::match('{\{x,ab}', '{x'));
        $this->assertTrue(DoubleStar::match('{a\,b}', 'a,b'));
        $this->assertTrue(DoubleStar::match('{a\}}', 'a}'));
        $this->assertTrue(DoubleStar::match('{a\\\\}', 'a\\'));
        // a literal `]` does not satisfy a `}` in the value
        $this->assertFalse(DoubleStar::match('{a}]', 'a}'));
    }

    public function testBraceWithMalformedAlternatives()
    {
        // a malformed alternative aborts the whole alternation
        $this->assertFalse(DoubleStar::match('{[,b}', 'b'));
        $this->assertFalse(DoubleStar::match('{a[,b}', 'b'));
        $this->assertFalse(DoubleStar::match('{[}],x}', '}'));
        $this->assertFalse(DoubleStar::match('{[a,b],c}', 'a'));
        $this->assertFalse(DoubleStar::match('{[a,b],c}', ','));
        $this->assertFalse(DoubleStar::match('{[a,],x}', 'a'));
        $this->assertFalse(DoubleStar::match('{a,b', 'a'));
        $this->assertFalse(DoubleStar::match('{a,b', ''));
    }

    public function testZeroLengthPatternSpecials()
    {
        $this->assertTrue(DoubleStar::match('', ''));
        $this->assertTrue(DoubleStar::match('*', ''));
        $this->assertTrue(DoubleStar::match('a*', 'a'));
        $this->assertTrue(DoubleStar::match('a**', 'a'));
        $this->assertTrue(DoubleStar::match('**/', ''));
        $this->assertTrue(DoubleStar::match('/**/', '/'));
        $this->assertTrue(DoubleStar::match('/**/', ''));
        $this->assertTrue(DoubleStar::match('a/**/', 'a/'));
        $this->assertTrue(DoubleStar::match('{a,}', 'a'));
        $this->assertTrue(DoubleStar::match('{a,}', ''));
        $this->assertTrue(DoubleStar::match('{,a}', ''));
        $this->assertFalse(DoubleStar::match('{{a,b},c}', ''));
    }

    public function testMalformedPatternsDoNotMatch()
    {
        $this->assertFalse(DoubleStar::match('[abc', 'x'));
        $this->assertFalse(DoubleStar::match('[]', 'x'));
        $this->assertFalse(DoubleStar::match('[!]', 'x'));
        $this->assertFalse(DoubleStar::match('a\\', 'a'));
        $this->assertFalse(DoubleStar::match('a\\', 'a\\'));
        $this->assertFalse(DoubleStar::match('a[!', 'a'));
        $this->assertFalse(DoubleStar::match('a[b', 'ab'));
        // a valid tail after a failed class simply does not match
        $this->assertFalse(DoubleStar::match('a[b]c', 'axd'));
        // class failure falls back to the star backtracking positions
        $this->assertFalse(DoubleStar::match('*[bc]', 'ax'));
        $this->assertFalse(DoubleStar::match('*[!a]', 'aa'));
    }

    public function testClassRangesWithEscapes()
    {
        // an escaped rune after a `-` is the escaped range bound
        $this->assertTrue(DoubleStar::match('x[+-\<]y', 'x<y'));
        $this->assertFalse(DoubleStar::match('x[+-\<]y', 'x=y'));
        $this->assertFalse(DoubleStar::match('x[+-\<]y', 'xxy'));
        // a plain escaped dash is a class member, not a range operator
        $this->assertTrue(DoubleStar::match('a[a\-z]c', 'a-c'));
        $this->assertFalse(DoubleStar::match('a[a\-z]c', 'ac'));
        // an out-of-range value resets the pending range and keeps scanning
        $this->assertFalse(DoubleStar::match('x[+-\;]y', 'x>y'));
        $this->assertFalse(DoubleStar::match('x[+-\;]y', 'xxy'));
    }

    public function testClassFailureBacktracking()
    {
        // the star backtracks over the value and the class is re-entered at
        // the end of the value, decoding an error rune of width 0
        $this->assertFalse(DoubleStar::match('*[b]', 'a'));
        $this->assertTrue(DoubleStar::match('*[b]', 'ab'));
        $this->assertFalse(DoubleStar::match('a*[bc]', 'ax'));
        $this->assertFalse(DoubleStar::match('abx', 'a*[b]'));
    }

    public function testMalformedTailsDuringValidation()
    {
        // an escaped byte inside a class during validation
        $this->assertFalse(DoubleStar::match('a[b\]]x', 'aX'));
        // a dangling escape at the end of the remaining pattern
        $this->assertFalse(DoubleStar::match('a[b]c\\', 'ax'));
        // an unterminated brace alternation in the remaining pattern
        $this->assertFalse(DoubleStar::match('a[b]{c', 'ax'));
        $this->assertFalse(DoubleStar::match('a[b]{c\q', 'aX'));
        // a stray closing brace in the remaining pattern
        $this->assertFalse(DoubleStar::match('a[b]}c', 'ax'));
        // an unterminated class in the remaining pattern
        $this->assertFalse(DoubleStar::match('x[b\c', 'aX'));
        // well-formed tails that cannot match simply do not match
        $this->assertFalse(DoubleStar::match('a**b]c', 'x'));
        $this->assertFalse(DoubleStar::match('a[b]{c}', 'x'));
    }

    public function testDecodeRuneBranches()
    {
        // an invalid continuation byte decodes as U+FFFD on both sides
        $this->assertTrue(DoubleStar::match("\xC3x", "\xC3x"));
        $this->assertTrue(DoubleStar::match("\xC3(\x80", "\xC3(\x80"));
        // an overlong 3-byte lead with a second byte below 0xA0
        $this->assertTrue(DoubleStar::match("\xE0\x9F\x98x", "\xE0\x9F\x98x"));
        // a truncated 3-byte sequence
        $this->assertTrue(DoubleStar::match("\xE0\xA0x", "\xE0\xA0x"));
        // 4-byte sequences, including the largest code point
        $this->assertTrue(DoubleStar::match("\xF0\x9F\x98\x80x", "\xF0\x9F\x98\x80x"));
        $this->assertTrue(DoubleStar::match("A\xF4\x8F\xBF\xBF", "A\xF4\x8F\xBF\xBF"));
        // truncated sequence at the end of the string
        $this->assertTrue(DoubleStar::match("a\xC3", "a\xC3"));
    }

    public function testUnreachedMalformedParts()
    {
        // Malformed parts the matcher never reaches do not affect the
        // result - once an earlier brace alternative has matched, later
        // alternatives are not evaluated, and an early `**` match skips the
        // rest of the pattern.
        $this->assertTrue(DoubleStar::match('a}/**', 'a}/secret'));
        $this->assertTrue(DoubleStar::match('{ok,[}', 'ok'));
    }

    public function testInvalidUtf8()
    {
        // Overlong, surrogate and out-of-range encodings are rejected by the
        // decoder: no byte of an invalid sequence can act as a path separator.
        $this->assertFalse(DoubleStar::match('**/admin', "\xC0\xAFadmin"));
        $this->assertFalse(DoubleStar::match('**/admin', "\xE0\x80\xAFadmin"));
        $this->assertFalse(DoubleStar::match('**/admin', "\xF0\x80\x80\xAFadmin"));
        $this->assertFalse(DoubleStar::match('x?', "\xED\xA0\x80"));
        $this->assertFalse(DoubleStar::match('**/admin', "\xF4\x90\x80\x80admin"));

        // Valid multi-byte runes keep matching.
        $this->assertTrue(DoubleStar::match('/数据/**', '/数据/列表/详情'));
        $this->assertTrue(DoubleStar::match('/数据/?详情', '/数据/查详情'));
        $this->assertFalse(DoubleStar::match('/数据/*', '/数据/列/表'));

        // Identical invalid sequences on both sides match byte by byte, each
        // byte decoding as an error rune of width 1.
        $this->assertTrue(DoubleStar::match("\xC0\xAF", "\xC0\xAF"));
    }

    public static function globMatchCasesProvider(): array
    {
        return [
            ['/foo', '/foo', true],
            ['/foo', '/foo*', true],
            ['/foo', '/foo/*', false],
            ['/foo/bar', '/foo', false],
            ['/foo/bar', '/foo*', false],
            ['/foo/bar', '/foo/*', true],
            ['/foobar', '/foo', false],
            ['/foobar', '/foo*', true],
            ['/foobar', '/foo/*', false],

            ['/foo', '*/foo', true],
            ['/foo', '*/foo*', true],
            ['/foo', '*/foo/*', false],
            ['/foo/bar', '*/foo', false],
            ['/foo/bar', '*/foo*', false],
            ['/foo/bar', '*/foo/*', true],
            ['/foobar', '*/foo', false],
            ['/foobar', '*/foo*', true],
            ['/foobar', '*/foo/*', false],

            ['/prefix/foo', '*/foo', false],
            ['/prefix/foo', '*/foo*', false],
            ['/prefix/foo', '*/foo/*', false],
            ['/prefix/foo/bar', '*/foo', false],
            ['/prefix/foo/bar', '*/foo*', false],
            ['/prefix/foo/bar', '*/foo/*', false],
            ['/prefix/foobar', '*/foo', false],
            ['/prefix/foobar', '*/foo*', false],
            ['/prefix/foobar', '*/foo/*', false],

            ['/prefix/subprefix/foo', '*/foo', false],
            ['/prefix/subprefix/foo', '*/foo*', false],
            ['/prefix/subprefix/foo', '*/foo/*', false],
            ['/prefix/subprefix/foo/bar', '*/foo', false],
            ['/prefix/subprefix/foo/bar', '*/foo*', false],
            ['/prefix/subprefix/foo/bar', '*/foo/*', false],
            ['/prefix/subprefix/foobar', '*/foo', false],
            ['/prefix/subprefix/foobar', '*/foo*', false],
            ['/prefix/subprefix/foobar', '*/foo/*', false],

            ['/foo', '**/foo', true],
            ['/foo', '**/foo**', true],
            ['/foo', '**/foo/**', true],
            ['/foo/bar', '**/foo', false],
            ['/foo/bar', '**/foo**', false],
            ['/foo/bar', '**/foo/**', true],
            ['/foobar', '**/foo', false],
            ['/foobar', '**/foo**', true],
            ['/foobar', '**/foo/**', false],

            ['/prefix/foo', '**/foo', true],
            ['/prefix/foo', '**/foo**', true],
            ['/prefix/foo', '**/foo/**', true],
            ['/prefix/foo/bar', '**/foo', false],
            ['/prefix/foo/bar', '**/foo**', false],
            ['/prefix/foo/bar', '**/foo/**', true],
            ['/prefix/foobar', '**/foo', false],
            ['/prefix/foobar', '**/foo**', true],
            ['/prefix/foobar', '**/foo/**', false],

            ['/prefix/subprefix/foo', '**/foo', true],
            ['/prefix/subprefix/foo', '**/foo**', true],
            ['/prefix/subprefix/foo', '**/foo/**', true],
            ['/prefix/subprefix/foo/bar', '**/foo', false],
            ['/prefix/subprefix/foo/bar', '**/foo**', false],
            ['/prefix/subprefix/foo/bar', '**/foo/**', true],
            ['/prefix/subprefix/foobar', '**/foo', false],
            ['/prefix/subprefix/foobar', '**/foo**', true],
            ['/prefix/subprefix/foobar', '**/foo/**', false],

            ['/foo', '*/foo**', true],
            ['/foo', '**/foo*', true],
            ['/foo', '*/foo/**', true],
            ['/foo', '**/foo/*', false],
            ['/foo/bar', '*/foo**', false],
            ['/foo/bar', '**/foo*', false],
            ['/foo/bar', '*/foo/**', true],
            ['/foo/bar', '**/foo/*', true],
            ['/foobar', '*/foo**', true],
            ['/foobar', '**/foo*', true],
            ['/foobar', '*/foo/**', false],
            ['/foobar', '**/foo/*', false],

            ['/prefix/foo', '*/foo**', false],
            ['/prefix/foo', '**/foo*', true],
            ['/prefix/foo', '*/foo/**', false],
            ['/prefix/foo', '**/foo/*', false],
            ['/prefix/foo/bar', '*/foo**', false],
            ['/prefix/foo/bar', '**/foo*', false],
            ['/prefix/foo/bar', '*/foo/**', false],
            ['/prefix/foo/bar', '**/foo/*', true],
            ['/prefix/foobar', '*/foo**', false],
            ['/prefix/foobar', '**/foo*', true],
            ['/prefix/foobar', '*/foo/**', false],
            ['/prefix/foobar', '**/foo/*', false],

            ['/prefix/subprefix/foo', '*/foo**', false],
            ['/prefix/subprefix/foo', '**/foo*', true],
            ['/prefix/subprefix/foo', '*/foo/**', false],
            ['/prefix/subprefix/foo', '**/foo/*', false],
            ['/prefix/subprefix/foo/bar', '*/foo**', false],
            ['/prefix/subprefix/foo/bar', '**/foo*', false],
            ['/prefix/subprefix/foo/bar', '*/foo/**', false],
            ['/prefix/subprefix/foo/bar', '**/foo/*', true],
            ['/prefix/subprefix/foobar', '*/foo**', false],
            ['/prefix/subprefix/foobar', '**/foo*', true],
            ['/prefix/subprefix/foobar', '*/foo/**', false],
            ['/prefix/subprefix/foobar', '**/foo/*', false],
        ];
    }
}
