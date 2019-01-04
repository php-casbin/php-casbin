<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Log\Log;
use Casbin\Log\Logger\DefaultLogger;

/**
 * LogTest.
 *
 * @author techlee@qq.com
 */
class LogTest extends TestCase
{
    public function testLog()
    {
        $logger = new DefaultLogger();
        Log::setLogger($logger);
        Log::getLogger()->enableLog(true);
        $enable = Log::getLogger()->isEnabled();
        $this->assertTrue($enable);

        Log::getLogger()->enableLog(false);
        $enable = Log::getLogger()->isEnabled();
        $this->assertFalse($enable);
    }
}
