<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Util\BuiltinOperations;
use Closure;

/**
 * Class FunctionMap.
 *
 * @author techlee@qq.com
 */
class FunctionMap
{
    /**
     * @var array<string, Closure>
     */
    private $functions = [];

    /**
     * @param string $name
     * @param Closure $func
     */
    public function addFunction(string $name, Closure $func): void
    {

        $this->functions[$name] = $func;
    }

    /**
     * Loads an initial function map.
     *
     * @return FunctionMap
     */
    public static function loadFunctionMap(): self
    {
        $fm = new self();

        $fm->addFunction('keyMatch', function (...$args) {
            return BuiltinOperations::keyMatchFunc(...$args);
        });
        $fm->addFunction('keyGet', function (...$args) {
            return BuiltinOperations::keyGetFunc(...$args);
        });
        $fm->addFunction('keyMatch2', function (...$args) {
            return BuiltinOperations::keyMatch2Func(...$args);
        });
        $fm->addFunction('keyGet2', function (...$args) {
            return BuiltinOperations::keyGet2Func(...$args);
        });
        $fm->addFunction('keyMatch3', function (...$args) {
            return BuiltinOperations::keyMatch3Func(...$args);
        });
        $fm->addFunction('keyMatch4', function (...$args) {
            return BuiltinOperations::keyMatch4Func(...$args);
        });
        $fm->addFunction('keyMatch5', function (...$args) {
            return BuiltinOperations::keyMatch5Func(...$args);
        });
        $fm->addFunction('regexMatch', function (...$args) {
            return BuiltinOperations::regexMatchFunc(...$args);
        });
        $fm->addFunction('ipMatch', function (...$args) {
            return BuiltinOperations::ipMatchFunc(...$args);
        });
        $fm->addFunction('globMatch', function (...$args) {
            return BuiltinOperations::globMatchFunc(...$args);
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
