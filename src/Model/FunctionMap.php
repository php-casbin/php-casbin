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
    private array $functions = [];

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

        $fm->addFunction('keyMatch', fn(...$args) => BuiltinOperations::keyMatchFunc(...$args));
        $fm->addFunction('keyGet', fn(...$args) => BuiltinOperations::keyGetFunc(...$args));
        $fm->addFunction('keyMatch2', fn(...$args) => BuiltinOperations::keyMatch2Func(...$args));
        $fm->addFunction('keyGet2', fn(...$args) => BuiltinOperations::keyGet2Func(...$args));
        $fm->addFunction('keyMatch3', fn(...$args) => BuiltinOperations::keyMatch3Func(...$args));
        $fm->addFunction('keyMatch4', fn(...$args) => BuiltinOperations::keyMatch4Func(...$args));
        $fm->addFunction('keyMatch5', fn(...$args) => BuiltinOperations::keyMatch5Func(...$args));
        $fm->addFunction('regexMatch', fn(...$args) => BuiltinOperations::regexMatchFunc(...$args));
        $fm->addFunction('ipMatch', fn(...$args) => BuiltinOperations::ipMatchFunc(...$args));
        $fm->addFunction('globMatch', fn(...$args) => BuiltinOperations::globMatchFunc(...$args));

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
