<?php

namespace Casbin\Log;

/**
 * Logger interface.
 */
interface Logger
{
    //EnableLog controls whether print the message.
    public function enableLog($enable);

    //IsEnabled returns if logger is enabled.
    public function isEnabled();

    //Print formats using the default formats for its operands and logs the message.
    public function print(...$v);

    //Printf formats according to a format specifier and logs the message.
    public function printf($format, ...$v);
}
