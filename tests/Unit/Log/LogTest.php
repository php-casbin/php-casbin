<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Log\Log;
use Casbin\Log\Logger;
use Mockery;

/**
 * LogTest.
 *
 * @author techlee@qq.com
 */
class LogTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function testLog()
    {
        $this->expectNotToPerformAssertions();

        $logger = Mockery::mock(Logger::class);
        $logger->shouldReceive('enableLog')
            ->once()
            ->with(true);
        $logger->shouldReceive('isEnabled')
            ->once()
            ->andReturn(true);
        $logger->shouldReceive('logPolicy')
            ->once()
            ->with([]);
        $logger->shouldReceive('logModel')
            ->once()
            ->with([]);
        $logger->shouldReceive('logEnforce')
            ->once()
            ->with('my_matcher', ['bob'], true, []);
        $logger->shouldReceive('logRole')
            ->once()
            ->with([]);
        $logger->shouldReceive('logError')
            ->once()
            ->with(Mockery::type(\Exception::class), 'test');
        /** @var Logger $logger */
        Log::setLogger($logger);

        Log::getLogger()->enableLog(true);
        Log::getLogger()->isEnabled();
        Log::logModel([]);
        Log::logEnforce('my_matcher', ['bob'], true, []);
        Log::logPolicy([]);
        Log::logRole([]);
        Log::logError(new \Exception(), 'test');
    }
}
