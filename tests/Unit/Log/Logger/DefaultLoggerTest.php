<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Log\Logger\DefaultLogger;
use Mockery;

/**
 * DefaultLoggerTest.
 *
 * @author techlee@qq.com
 */
class DefaultLoggerTest extends TestCase
{
    public function testDefaultLogger()
    {
        $logger = new DefaultLogger();

        $logger->enableLog(true);
        $enable = $logger->isEnabled();
        $this->assertTrue($enable);

        $logfile = $logger->psrLogger->path;
        if (file_exists($logfile)) {
            unlink($logfile);
        }

        $logger->logModel([]);
        $logger->logEnforce('my_matcher', ['bob'], true, []);
        $logger->logPolicy([]);
        $logger->logRole([]);
        $logger->logError(new \Exception('test'));
        $pattern = '/^.*? INFO: Model:\s*' . PHP_EOL .
            '^.*? INFO: Request: bob ---> true' . PHP_EOL .
            'Hit Policy:\s*' . PHP_EOL .
            '^.*? INFO: Policy:\s*' . PHP_EOL .
            '^.*? INFO: Roles:\s*' . PHP_EOL .
            '^.*? ERROR: test' . PHP_EOL . '$/m';

        $this->assertTrue(file_exists($logfile));
        $this->assertMatchesRegularExpression($pattern, file_get_contents($logfile));

        $logger->enableLog(false);
        $enable = $logger->isEnabled();
        $this->assertFalse($enable);
        // reach the `return` statement inside
        $logger->logModel([]);
        $logger->logEnforce('my_matcher', ['bob'], true, []);
        $logger->logPolicy([]);
        $logger->logRole([]);
        $logger->logError(new \Exception('test'));
    }

    public function testDefaultLoggerWithPsrLogger()
    {
        $this->expectNotToPerformAssertions();
        $psrLogger = Mockery::mock(\Psr\Log\AbstractLogger::class);
        $psrLogger->shouldReceive('info')->withAnyArgs()->andReturn(null);
        $psrLogger->shouldReceive('error')->withAnyArgs()->andReturn(null);

        $logger = new DefaultLogger($psrLogger);
        $logger->enableLog(true);
        $logger->logModel([]);
        $logger->logEnforce('my_matcher', ['bob'], true, []);
        $logger->logPolicy([]);
        $logger->logRole([]);
        $logger->logError(new \Exception('test'));

        $psrLogger->shouldHaveReceived('info')->atLeast()->times(4);
        $psrLogger->shouldHaveReceived('error')->atLeast()->times(1);
        Mockery::close();
    }
}
