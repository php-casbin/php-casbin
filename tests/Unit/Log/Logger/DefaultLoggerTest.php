<?php

namespace Casbin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Casbin\Log\Logger\DefaultLogger;

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

        $path = $logger->path;
        $name = $logger->name;
        $logfile = $logger->path . DIRECTORY_SEPARATOR . $logger->name;

        if (file_exists($logfile)) {
            unlink($logfile);
        }
        $logger->write('testing logger');

        $logger->write(['testing', 'logger']);

        $logger->writef('testing %s', 'DefaultLogger');

        $this->assertTrue(file_exists($logfile));
    }
}
