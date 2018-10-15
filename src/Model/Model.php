<?php
namespace Casbin\Model;

use Casbin\Config\Config;
use Casbin\Util\Log;
use Casbin\Util\Util;

/**
 * Model
 * @author techlee@qq.com
 */
class Model
{

    use Policy;

    public $model = [];

    protected $sectionNameMap = [
        "r" => "request_definition",
        "p" => "policy_definition",
        "g" => "role_definition",
        "e" => "policy_effect",
        "m" => "matchers",
    ];

    public function __construct()
    {

    }

    private function loadAssertion($cfg, $sec, $key)
    {
        $value = $cfg->getString($this->sectionNameMap[$sec] . '::' . $key);
        return $this->addDef($sec, $key, $value);
    }

    public function addDef($sec, $key, $value)
    {
        if ($value == '') {
            return;
        }
        $ast        = new Assertion;
        $ast->key   = $key;
        $ast->value = $value;

        if ($sec == "r" || $sec == "p") {
            $ast->tokens = explode(', ', $ast->value);
            foreach ($ast->tokens as $i => $token) {
                $ast->tokens[$i] = $key . '_' . $token;
            }
        } else {
            $ast->value = Util::removeComments(Util::escapeAssertion($ast->value));
        }

        $this->model[$sec][$key] = $ast;

        return true;
    }

    private function getKeySuffix($i)
    {
        if ($i == 1) {
            return '';
        }
        return (string) $i;
    }

    private function loadSection($cfg, $sec)
    {
        $i = 1;
        for (;;) {
            if (!$this->loadAssertion($cfg, $sec, $sec . $this->getKeySuffix($i))) {
                break;
            } else {
                $i++;
            }
        }
    }

    public function loadModel($path)
    {
        $cfg = Config::newConfig($path);

        $this->loadSection($cfg, 'r');
        $this->loadSection($cfg, 'p');
        $this->loadSection($cfg, 'e');
        $this->loadSection($cfg, 'm');

        $this->loadSection($cfg, 'g');
    }

    public function loadModelFromText()
    {

    }

    public function printModel()
    {
        Log::logPrint("Model:");
        foreach ($this->model as $k => $v) {
            foreach ($v as $i => $j) {
                Log::logPrintf("%s.%s: %s", $k, $i, $j->value);
            }
        }
    }

}
