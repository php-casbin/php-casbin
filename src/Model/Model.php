<?php

namespace Casbin\Model;

use Casbin\Config\Config;
use Casbin\Config\ConfigContract;
use Casbin\Log\Log;
use Casbin\Util\Util;

/**
 * Class Model.
 *
 * @author techlee@qq.com
 */
class Model
{
    use Policy;

    /**
     * @var array
     */
    public $model = [];

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
     * @return bool|void
     */
    private function loadAssertion($cfg, $sec, $key)
    {
        $value = $cfg->getString($this->sectionNameMap[$sec].'::'.$key);

        return $this->addDef($sec, $key, $value);
    }

    /**
     * adds an assertion to the model.
     *
     * @param string $sec
     * @param string $key
     * @param mixed  $value
     *
     * @return bool|void
     */
    public function addDef($sec, $key, $value)
    {
        if ('' == $value) {
            return;
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

        $this->model[$sec][$key] = $ast;

        return true;
    }

    /**
     * @param $i
     *
     * @return string
     */
    private function getKeySuffix($i)
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
    private function loadSection($cfg, $sec)
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
    public static function newModel()
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
    public static function newModelFromFile($path)
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
    public static function newModelFromString($text)
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
    public function loadModel($path)
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
    public function loadModelFromText($text)
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
    public function printModel()
    {
        Log::logPrint('Model:');
        foreach ($this->model as $k => $v) {
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
    public static function loadFunctionMap()
    {
        return FunctionMap::loadFunctionMap();
    }
}
