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

    //write formats using the default formats for its operands and logs the message.
    public function write(...$v);

    //writef formats according to a format specifier and logs the message.
    public function writef($format, ...$v);
}
