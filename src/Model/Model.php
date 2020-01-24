<?php

declare(strict_types=1);

namespace Casbin\Model;

use ArrayAccess;
use Casbin\Config\Config;
use Casbin\Config\ConfigContract;
use Casbin\Log\Log;
use Casbin\Util\Util;

/**
 * Class Model.
 *
 * @implements ArrayAccess<string|int, mixed>
 *
 * @author techlee@qq.com
 */
class Model implements ArrayAccess
{
    use Policy;

    /**
     * All of the Model items.
     *
     * @var array
     */
    protected $items = [];

    protected $sectionNameMap = [
        'r' => 'request_definition',
        'p' => 'policy_definition',
        'g' => 'role_definition',
        'e' => 'policy_effect',
        'm' => 'matchers',
    ];

    public function __construct()
    {
    }

    /**
     * @param ConfigContract $cfg
     * @param string         $sec
     * @param string         $key
     *
     * @return bool
     */
    private function loadAssertion(ConfigContract $cfg, string $sec, string $key): bool
    {
        $value = $cfg->getString($this->sectionNameMap[$sec].'::'.$key);

        return $this->addDef($sec, $key, $value);
    }

    /**
     * adds an assertion to the model.
     *
     * @param string $sec
     * @param string $key
     * @param string $value
     *
     * @return bool
     */
    public function addDef(string $sec, string $key, string $value): bool
    {
        if ('' == $value) {
            return false;
        }

        $ast = new Assertion();
        $ast->key = $key;
        $ast->value = $value;

        if ('r' == $sec || 'p' == $sec) {
            $ast->tokens = explode(', ', $ast->value);
            foreach ($ast->tokens as $i => $token) {
                $ast->tokens[$i] = $key.'_'.$token;
            }
        } else {
            $ast->value = Util::removeComments(Util::escapeAssertion($ast->value));
        }

        $this->items[$sec][$key] = $ast;

        return true;
    }

    /**
     * @param int $i
     *
     * @return string
     */
    private function getKeySuffix(int $i): string
    {
        if (1 == $i) {
            return '';
        }

        return (string) $i;
    }

    /**
     * @param ConfigContract $cfg
     * @param string         $sec
     */
    private function loadSection(ConfigContract $cfg, string $sec): void
    {
        $i = 1;
        for (; ;) {
            if (!$this->loadAssertion($cfg, $sec, $sec.$this->getKeySuffix($i))) {
                break;
            } else {
                ++$i;
            }
        }
    }

    /**
     * creates an empty model.
     *
     * @return Model
     */
    public static function newModel(): self
    {
        return new self();
    }

    /**
     * creates a model from a .CONF file.
     *
     * @param string $path
     *
     * @return Model
     */
    public static function newModelFromFile(string $path): self
    {
        $m = self::newModel();

        $m->loadModel($path);

        return $m;
    }

    /**
     * creates a model from a string which contains model text.
     *
     * @param string $text
     *
     * @return Model
     */
    public static function newModelFromString(string $text): self
    {
        $m = self::newModel();

        $m->loadModelFromText($text);

        return $m;
    }

    /**
     * loads the model from model CONF file.
     *
     * @param string $path
     */
    public function loadModel(string $path): void
    {
        $cfg = Config::newConfig($path);

        $this->loadSection($cfg, 'r');
        $this->loadSection($cfg, 'p');
        $this->loadSection($cfg, 'e');
        $this->loadSection($cfg, 'm');

        $this->loadSection($cfg, 'g');
    }

    /**
     * loads the model from the text.
     *
     * @param string $text
     */
    public function loadModelFromText(string $text): void
    {
        $cfg = Config::newConfigFromText($text);

        $this->loadSection($cfg, 'r');
        $this->loadSection($cfg, 'p');
        $this->loadSection($cfg, 'e');
        $this->loadSection($cfg, 'm');

        $this->loadSection($cfg, 'g');
    }

    /**
     * prints the model to the log.
     */
    public function printModel(): void
    {
        Log::logPrint('Model:');
        foreach ($this->items as $k => $v) {
            foreach ($v as $i => $j) {
                Log::logPrintf('%s.%s: %s', $k, $i, $j->value);
            }
        }
    }

    /**
     * loads an initial function map.
     *
     * @return FunctionMap
     */
    public static function loadFunctionMap(): FunctionMap
    {
        return FunctionMap::loadFunctionMap();
    }

    /**
     * Determine if the given Model option exists.
     *
     * @param mixed $offset
     *
     * @return bool
     */
    public function offsetExists($offset)
    {
        return isset($this->items[$offset]);
    }

    /**
     * Get a Model option.
     *
     * @param mixed $offset
     *
     * @return mixed
     */
    public function offsetGet($offset)
    {
        return isset($this->items[$offset]) ? $this->items[$offset] : null;
    }

    /**
     * Set a Model option.
     *
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->items[] = $value;
        } else {
            $this->items[$offset] = $value;
        }
    }

    /**
     * Unset a Model option.
     *
     * @param mixed $offset
     */
    public function offsetUnset($offset)
    {
        unset($this->items[$offset]);
    }
}
