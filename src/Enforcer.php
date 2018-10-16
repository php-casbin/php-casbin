<?php
namespace Casbin;

use Casbin\Effect\DefaultEffector as Effector;
use Casbin\Exceptions\CasbinException;
use Casbin\Model\FunctionMap;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Casbin\Util\BuiltinOperations;
use Casbin\Util\Log;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

/**
 * Enforcer is the main interface for authorization enforcement and policy management.
 * @author techlee@qq.com
 */
class Enforcer
{
    /**
     * model path
     * @var string
     */
    protected $modelPath;

    /**
     * Model
     * @var Model
     */
    protected $model;

    /**
     * FunctionMap
     * @var FunctionMap
     */
    protected $fm;

    /**
     * Effector
     * @var Effector
     */
    protected $eft;

    /**
     * Adapter
     * @var Adapter
     */
    protected $adapter;

    protected $watcher;

    /**
     * RoleManager
     * @var RoleManager
     */
    protected $rm;

    /**
     * $autoSave
     * @var boolean
     */
    protected $autoSave = true;

    /**
     * $autoBuildRoleLinks
     * @var boolean
     */
    protected $autoBuildRoleLinks = true;

    public function __construct($model, $policy)
    {
        if (is_string($policy)) {
            $this->initWithFile($model, $policy);
        } else {
            $this->initWithAdapter($model, $policy);
        }
    }

    /**
     * initializes an enforcer with a model file and a policy file.
     * @param  string  $modelPath
     * @param  string $policyPath
     */
    public function initWithFile($modelPath, $policyPath)
    {
        $adapter = new FileAdapter($policyPath);
        $this->initWithAdapter($modelPath, $adapter);
    }

    /**
     * initWithAdapter initializes an enforcer with a database adapter.
     * @param  string  $modelPath
     * @param  Adapter $adapter
     */
    public function initWithAdapter($modelPath, Adapter $adapter)
    {
        $m = $this->newModel($modelPath, "");
        $this->initWithModelAndAdapter($m, $adapter);

        $this->modelPath = $modelPath;
    }

    public function initWithModelAndAdapter($m, Adapter $adapter)
    {
        $this->adapter = $adapter;

        $this->model = $m;
        $this->model->printModel();

        $this->fm = FunctionMap::loadFunctionMap();

        $this->initialize();

        if (!is_null($this->adapter)) {
            $this->loadPolicy();
        }
    }

    protected function initialize()
    {
        $this->rm      = new RoleManager(10);
        $this->eft     = new Effector();
        $this->watcher = null;

        $this->enabled            = true;
        $this->autoSave           = true;
        $this->autoBuildRoleLinks = true;
    }

    public function newModel(...$text)
    {
        $model = new Model();
        if (count($text) == 2) {
            if ($text[0] != "") {
                $model->loadModel($text[0]);
            }
        } elseif (count($text) == 1) {
            $model->loadModel($text[0]);
        } elseif (count($text) != 0) {
            throw new CasbinException("Invalid parameters for model.");
        }

        return $model;
    }

    public function loadPolicy()
    {
        $this->model->clearPolicy();
        $this->adapter->loadPolicy($this->model);

        $this->model->printPolicy();

        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }
    }

    public function buildRoleLinks()
    {
        $this->rm->clear();
        $this->model->buildRoleLinks($this->rm);
    }

    public function enforce(...$rvals)
    {
        if (!$this->enabled) {
            return true;
        }

        $functions = [];
        foreach ($this->fm->getFunctions() as $key => $func) {
            $functions[$key] = $func;
        }

        if (isset($this->model->model['g'])) {
            foreach ($this->model->model['g'] as $key => $ast) {
                $rm              = $ast->rM;
                $functions[$key] = BuiltinOperations::GenerateGFunction($rm);
            }
        }
        if (!isset($this->model->model['m']['m'])) {
            throw new CasbinException('model is undefined');
        }
        $expString = $this->model->model['m']['m']->value;

        $policyEffects  = [];
        $matcherResults = [];

        $policyLen = count($this->model->model['p']['p']->policy);

        if ($policyLen != 0) {
            foreach ($this->model->model['p']['p']->policy as $i => $pvals) {
                $parameters = [];
                foreach ($this->model->model['r']['r']->tokens as $j => $token) {
                    $parameters[$token] = $rvals[$j];
                }

                foreach ($this->model->model['p']['p']->tokens as $j => $token) {
                    $parameters[$token] = $pvals[$j];
                }
                $result = $this->expressionEvaluate($expString, $parameters, $functions);

                if (is_bool($result)) {
                    if (!$result) {
                        $policyEffects[$i] = Effector::INDETERMINATE;
                        continue;
                    }
                } elseif (is_float($result)) {
                    if ($result == 0) {
                        $policyEffects[$i] = Effector::INDETERMINATE;
                        continue;
                    } else {
                        $matcherResults[$i] = $result;
                    }
                } else {
                    throw new CasbinException("matcher result should be bool, int or float");
                }
                if (isset($parameters['p_eft'])) {
                    $eft = $parameters['p_eft'];
                    if ($eft == "allow") {
                        $policyEffects[$i] = Effector::ALLOW;
                    } elseif ($eft == "deny") {
                        $policyEffects[$i] = Effector::DENY;
                    } else {
                        $policyEffects[$i] = Effector::INDETERMINATE;
                    }
                } else {
                    $policyEffects[$i] = Effector::ALLOW;
                }

                if (isset($this->model->model["e"]["e"]) && $this->model->model["e"]["e"]->value == "priority(p_eft) || deny") {
                    break;
                }
            }
        } else {
            $parameters = [];
            foreach ($this->model->model['r']['r']->tokens as $j => $token) {
                $parameters[$token] = $rvals[$j];
            }

            foreach ($this->model->model['p']['p']->tokens as $token) {
                $parameters[$token] = '';
            }

            $result = $this->expressionEvaluate($expString, $parameters, $functions);

            if ($result) {
                $policyEffects[0] = Effector::ALLOW;
            } else {
                $policyEffects[0] = Effector::INDETERMINATE;
            }
        }

        $result = $this->eft->mergeEffects($this->model->model["e"]["e"]->value, $policyEffects, $matcherResults);

        if (Log::$enableLog) {
            $reqStr = "Request: ";
            $reqStr .= implode(', ', array_values($rvals));

            $reqStr .= sprintf(" ---> %s", (string) $result);
            Log::logPrint($reqStr);
        }
        return $result;
    }

    protected function expressionEvaluate($expString, $parameters, $functions)
    {
        $expressionLanguage = new ExpressionLanguage();
        foreach ($functions as $key => $func) {
            $expressionLanguage->register($key, function (...$args) use ($key) {
                return sprintf($key . '(%1$s)', implode(',', $args));
            }, function ($arguments, ...$args) use ($func) {
                return $func(...$args);
            });
        }
        $expressionLanguage->evaluate($expString, $parameters);
        // $expressionLanguage->compile($expString, array_keys($parameters));
        return $expressionLanguage->evaluate($expString, $parameters);
    }
}
