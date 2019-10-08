<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Util\BuiltinOperations;

/**
 * Class FunctionMap.
 *
 * @author techlee@qq.com
 */
class FunctionMap
{
    private $functions = [];

    /**
     * @param string   $name
     * @param \Closure $func
     */
    public function addFunction(string $name, \Closure $func): void
    {
        $this->functions[$name] = $func;
    }

    /**
     * loads an initial function map.
     *
     * @return FunctionMap
     */
    public static function loadFunctionMap(): self
    {
        $fm = new self();

        $fm->addFunction('keyMatch', function (...$args) {
            return BuiltinOperations::keyMatchFunc(...$args);
        });
        $fm->addFunction('keyMatch2', function (...$args) {
            return BuiltinOperations::keyMatch2Func(...$args);
        });
        $fm->addFunction('regexMatch', function (...$args) {
            return BuiltinOperations::regexMatchFunc(...$args);
        });
        $fm->addFunction('ipMatch', function (...$args) {
            return BuiltinOperations::ipMatchFunc(...$args);
        });

        return $fm;
    }

    /**
     * @return array
     */
    public function getFunctions(): array
    {
        return $this->functions;
    }
}
