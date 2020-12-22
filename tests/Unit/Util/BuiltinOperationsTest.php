<?php

namespace Casbin\Tests\Unit\Util;

use Casbin\Util\BuiltinOperations;
use PHPUnit\Framework\TestCase;

/**
 * RoleManagerTest.
 *
 * @author techlee@qq.com
 */
class BuiltinOperationsTest extends TestCase
{
    private function keyMatchFunc($name1, $name2)
    {
        return (bool)BuiltinOperations::keyMatchFunc($name1, $name2);
    }

    private function keyMatch2Func($name1, $name2)
    {
        return (bool)BuiltinOperations::keyMatch2Func($name1, $name2);
    }

    private function keyMatch3Func($name1, $name2)
    {
        return (bool)BuiltinOperations::keyMatch3Func($name1, $name2);
    }

    private function keyMatch4Func($name1, $name2)
    {
        return (bool)BuiltinOperations::keyMatch4Func($name1, $name2);
    }

    public function testKeyMatchFunc()
    {
        $this->assertTrue($this->keyMatchFunc('/foo', '/foo'));
        $this->assertTrue($this->keyMatchFunc('/foo', '/foo*'));
        $this->assertFalse($this->keyMatchFunc('/foo', '/foo/*'));
        $this->assertFalse($this->keyMatchFunc('/foo/bar', '/foo'));
        $this->assertTrue($this->keyMatchFunc('/foo/bar', '/foo*'));
        $this->assertTrue($this->keyMatchFunc('/foo/bar', '/foo/*'));
        $this->assertFalse($this->keyMatchFunc('/foobar', '/foo'));
        $this->assertTrue($this->keyMatchFunc('/foobar', '/foo*'));
        $this->assertFalse($this->keyMatchFunc('/foobar', '/foo/*'));
    }

    public function testKeyMatch2Func()
    {
        $this->assertTrue($this->keyMatch2Func('/foo', '/foo'));
        $this->assertTrue($this->keyMatch2Func('/foo', '/foo*'));
        $this->assertFalse($this->keyMatch2Func('/foo', '/foo/*'));
        $this->assertFalse($this->keyMatch2Func('/foo/bar', '/foo'));
        $this->assertFalse($this->keyMatch2Func('/foo/bar', '/foo*'));
        $this->assertTrue($this->keyMatch2Func('/foo/bar', '/foo/*'));
        $this->assertFalse($this->keyMatch2Func('/foobar', '/foo'));
        $this->assertFalse($this->keyMatch2Func('/foobar', '/foo*'));
        $this->assertFalse($this->keyMatch2Func('/foobar', '/foo/*'));

        $this->assertFalse($this->keyMatch2Func('/', '/:resource'));
        $this->assertTrue($this->keyMatch2Func('/resource1', '/:resource'));
        $this->assertFalse($this->keyMatch2Func('/myid', '/:id/using/:resId'));
        $this->assertTrue($this->keyMatch2Func('/myid/using/myresid', '/:id/using/:resId'));

        $this->assertFalse($this->keyMatch2Func('/proxy/myid', '/proxy/:id/*'));
        $this->assertTrue($this->keyMatch2Func('/proxy/myid/', '/proxy/:id/*'));
        $this->assertTrue($this->keyMatch2Func('/proxy/myid/res', '/proxy/:id/*'));
        $this->assertTrue($this->keyMatch2Func('/proxy/myid/res/res2', '/proxy/:id/*'));
        $this->assertTrue($this->keyMatch2Func('/proxy/myid/res/res2/res3', '/proxy/:id/*'));
        $this->assertFalse($this->keyMatch2Func('/proxy/', '/proxy/:id/*'));

        $this->assertTrue($this->keyMatch2Func('/alice', '/:id'));
        $this->assertTrue($this->keyMatch2Func('/alice/all', '/:id/all'));
        $this->assertFalse($this->keyMatch2Func('/alice', '/:id/all'));
        $this->assertFalse($this->keyMatch2Func('/alice/all', '/:id'));

        $this->assertFalse($this->keyMatch2Func('/alice/all', '/:/all'));
    }

    public function testKeyMatch3Func()
    {
        $this->assertTrue($this->keyMatch3Func('/foo', '/foo'));
        $this->assertTrue($this->keyMatch3Func('/foo', '/foo*'));
        $this->assertFalse($this->keyMatch3Func('/foo', '/foo/*'));
        $this->assertFalse($this->keyMatch3Func('/foo/bar', '/foo'));
        $this->assertFalse($this->keyMatch3Func('/foo/bar', '/foo*'));
        $this->assertTrue($this->keyMatch3Func('/foo/bar', '/foo/*'));
        $this->assertFalse($this->keyMatch3Func('/foobar', '/foo'));
        $this->assertFalse($this->keyMatch3Func('/foobar', '/foo*'));
        $this->assertFalse($this->keyMatch3Func('/foobar', '/foo/*'));

        $this->assertFalse($this->keyMatch3Func('/', '/{resource}'));
        $this->assertTrue($this->keyMatch3Func('/resource1', '/{resource}'));
        $this->assertFalse($this->keyMatch3Func('/myid', '/{id}/using/{resId}'));
        $this->assertTrue($this->keyMatch3Func('/myid/using/myresid', '/{id}/using/{resId}'));

        $this->assertFalse($this->keyMatch3Func('/proxy/myid', '/proxy/{id}/*'));
        $this->assertTrue($this->keyMatch3Func('/proxy/myid/', '/proxy/{id}/*'));
        $this->assertTrue($this->keyMatch3Func('/proxy/myid/res', '/proxy/{id}/*'));
        $this->assertTrue($this->keyMatch3Func('/proxy/myid/res/res2', '/proxy/{id}/*'));
        $this->assertTrue($this->keyMatch3Func('/proxy/myid/res/res2/res3', '/proxy/{id}/*'));
        $this->assertFalse($this->keyMatch3Func('/proxy/', '/proxy/{id}/*'));

        $this->assertFalse($this->keyMatch3Func('/myid/using/myresid', '/{id/using/{resId}'));
    }

    public function testKeyMatch4Func()
    {
        $this->assertTrue($this->keyMatch4Func('/parent/123/child/123', '/parent/{id}/child/{id}'));
        $this->assertFalse($this->keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{id}'));

        $this->assertTrue($this->keyMatch4Func('/parent/123/child/123', '/parent/{id}/child/{another_id}'));
        $this->assertTrue($this->keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{another_id}'));

        $this->assertTrue($this->keyMatch4Func('/parent/123/child/123/book/123', '/parent/{id}/child/{id}/book/{id}'));
        $this->assertFalse($this->keyMatch4Func('/parent/123/child/123/book/456', '/parent/{id}/child/{id}/book/{id}'));
        $this->assertFalse($this->keyMatch4Func('/parent/123/child/456/book/123', '/parent/{id}/child/{id}/book/{id}'));
        $this->assertFalse($this->keyMatch4Func('/parent/123/child/456/book/', '/parent/{id}/child/{id}/book/{id}'));
        $this->assertFalse($this->keyMatch4Func('/parent/123/child/456', '/parent/{id}/child/{id}/book/{id}'));

        $this->assertFalse($this->keyMatch4Func('/parent/123/child/123', '/parent/{i/d}/child/{i/d}'));
    }
}
