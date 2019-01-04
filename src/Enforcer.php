<?php

namespace Casbin;

use Casbin\Effect\DefaultEffector;
use Casbin\Effect\Effector;
use Casbin\Exceptions\CasbinException;
use Casbin\Model\FunctionMap;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use Casbin\Persist\Adapters\FileAdapter;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\Watcher;
use Casbin\Rbac\DefaultRoleManager\RoleManager as DefaultRoleManager;
use Casbin\Rbac\RoleManager;
use Casbin\Util\BuiltinOperations;
use Casbin\Log\Log;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

/**
 * Enforcer is the main interface for authorization enforcement and policy management.
 *
 * @author techlee@qq.com
 */
class Enforcer
{
    use InternalApi, ManagementApi, RbacApi;

    /**
     * model path.
     *
     * @var string
     */
    protected $modelPath;

    /**
     * Model.
     *
     * @var Model
     */
    protected $model;

    /**
     * FunctionMap.
     *
     * @var FunctionMap
     */
    protected $fm;

    /**
     * Effector.
     *
     * @var Effector
     */
    protected $eft;

    /**
     * Adapter.
     *
     * @var Adapter
     */
    protected $adapter;

    /**
     * Watcher.
     *
     * @var watcher
     */
    protected $watcher;

    /**
     * RoleManager.
     *
     * @var RoleManager
     */
    protected $rm;

    /**
     * $enabled.
     *
     * @var bool
     */
    protected $enabled;

    /**
     * $autoSave.
     *
     * @var bool
     */
    protected $autoSave;

    /**
     * $autoBuildRoleLinks.
     *
     * @var bool
     */
    protected $autoBuildRoleLinks;

    /**
     * Creates an enforcer via file or DB.
     *
     * File:
     * $e = new Enforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
     * MySQL DB:
     * $a = DatabaseAdapter::newAdapter([
     *      'type'     => 'mysql', // mysql,pgsql,sqlite,sqlsrv
     *      'hostname' => '127.0.0.1',
     *      'database' => 'test',
     *      'username' => 'root',
     *      'password' => '123456',
     *      'hostport' => '3306',
     *  ]);
     * $e = new Enforcer("path/to/basic_model.conf", $a).
     *
     * @author techlee@qq.com
     *
     * @param array|mixed ...$params
     */
    public function __construct(...$params)
    {
        $parsedParamLen = 0;
        if (\count($params) >= 1) {
            if (\is_bool($params[\count($params) - 1])) {
                $enableLog = $params[\count($params) - 1];
                $this->enableLog($enableLog);
                ++$parsedParamLen;
            }
        }

        if (2 == \count($params) - $parsedParamLen) {
            $p0 = $params[0];
            if (\is_string($p0)) {
                $p1 = $params[1];
                if (\is_string($p1)) {
                    $this->initWithFile($p0, $p1);
                } else {
                    $this->initWithAdapter($p0, $p1);
                }
            } else {
                if (\is_string($params[1])) {
                    throw new CasbinException('Invalid parameters for enforcer.');
                } else {
                    $this->initWithModelAndAdapter($p0, $params[1]);
                }
            }
        } elseif (1 == \count($params) - $parsedParamLen) {
            $p0 = $params[0];
            if (\is_string($p0)) {
                $this->initWithFile($p0, '');
            } else {
                $this->initWithModelAndAdapter($p0, null);
            }
        } elseif (0 == \count($params) - $parsedParamLen) {
            $this->initWithFile('', '');
        } else {
            throw new CasbinException('Invalid parameters for enforcer.');
        }
    }

    /**
     * initializes an enforcer with a model file and a policy file.
     *
     * @param string $modelPath
     * @param string $policyPath
     */
    public function initWithFile($modelPath, $policyPath)
    {
        $adapter = new FileAdapter($policyPath);
        $this->initWithAdapter($modelPath, $adapter);
    }

    /**
     * initWithAdapter initializes an enforcer with a database adapter.
     *
     * @param string  $modelPath
     * @param Adapter $adapter
     */
    public function initWithAdapter($modelPath, Adapter $adapter)
    {
        $m = self::newModel($modelPath, '');
        $this->initWithModelAndAdapter($m, $adapter);

        $this->modelPath = $modelPath;
    }

    /**
     * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     *
     * @param Model        $m
     * @param Adapter|null $adapter
     */
    public function initWithModelAndAdapter(Model $m, $adapter)
    {
        $this->adapter = $adapter;

        $this->model = $m;
        $this->model->printModel();

        $this->fm = Model::loadFunctionMap();

        $this->initialize();

        if (null !== $this->adapter) {
            try {
                $this->loadPolicy();
            } catch (\Exception $e) {
                // error intentionally ignored
            }
        }
    }

    protected function initialize()
    {
        $this->rm = new DefaultRoleManager(10);
        $this->eft = new DefaultEffector();
        $this->watcher = null;

        $this->enabled = true;
        $this->autoSave = true;
        $this->autoBuildRoleLinks = true;
    }

    public static function newModel(...$text)
    {
        $model = new Model();
        if (2 == \count($text)) {
            if ('' != $text[0]) {
                $model->loadModel($text[0]);
            }
        } elseif (1 == \count($text)) {
            $model->loadModelFromText($text[0]);
        } elseif (0 != \count($text)) {
            throw new CasbinException('Invalid parameters for model.');
        }

        return $model;
    }

    public function loadModel()
    {
        $this->model = self::newModel();
        $this->model->loadModel($this->modelPath);
        $this->model->printModel();
        $this->fm = Model::LoadFunctionMap();
    }

    public function getModel()
    {
        return $this->model;
    }

    public function setModel(Model $model)
    {
        $this->model = $model;
        $this->fm = $this->model->loadFunctionMap();
    }

    public function getAdapter()
    {
        return $this->adapter;
    }

    public function setAdapter(Adapter $adapter)
    {
        $this->adapter = $adapter;
    }

    public function setWatcher(Watcher $watcher)
    {
        $this->watcher = $watcher;
        $this->watcher->setUpdateCallback(function () {
            $this->loadPolicy();
        });
    }

    public function setRoleManager(RoleManager $rm)
    {
        $this->rm = $rm;
    }

    public function setEffector(Effector $eft)
    {
        $this->eft = $eft;
    }

    public function clearPolicy()
    {
        $this->model->clearPolicy();
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

    public function loadFilteredPolicy($filter)
    {
        $this->model->clearPolicy();

        if ($this->adapter instanceof FilteredAdapter) {
            $filteredAdapter = $this->adapter;
        } else {
            throw new CasbinException('filtered policies are not supported by this adapter');
        }
        $filteredAdapter->loadFilteredPolicy($this->model, $filter);

        $this->model->printPolicy();
        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }
    }

    public function isFiltered()
    {
        if (!$this->adapter instanceof FilteredAdapter) {
            return false;
        }

        $filteredAdapter = $this->adapter;
        $filteredAdapter->isFiltered();
    }

    public function savePolicy()
    {
        if ($this->isFiltered()) {
            throw new CasbinException('cannot save a filtered policy');
        }

        $this->adapter->savePolicy($this->model);

        if (null !== $this->watcher) {
            return $this->watcher->update();
        }
    }

    public function enableEnforce($enabled = true)
    {
        $this->enabled = $enabled;
    }

    public function enableLog($enabled = true)
    {
        Log::getLogger()->enableLog($enabled);
    }

    public function enableAutoSave($autoSave = true)
    {
        $this->autoSave = $autoSave;
    }

    public function enableAutoBuildRoleLinks($autoBuildRoleLinks = true)
    {
        $this->autoBuildRoleLinks = $autoBuildRoleLinks;
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
                $rm = $ast->rM;
                $functions[$key] = BuiltinOperations::GenerateGFunction($rm);
            }
        }

        if (!isset($this->model->model['m']['m'])) {
            throw new CasbinException('model is undefined');
        }
        $expString = $this->model->model['m']['m']->value;

        $policyEffects = [];
        $matcherResults = [];

        $policyLen = \count($this->model->model['p']['p']->policy);

        if (0 != $policyLen) {
            foreach ($this->model->model['p']['p']->policy as $i => $pvals) {
                $parameters = [];
                foreach ($this->model->model['r']['r']->tokens as $j => $token) {
                    $parameters[$token] = $rvals[$j];
                }

                foreach ($this->model->model['p']['p']->tokens as $j => $token) {
                    $parameters[$token] = $pvals[$j];
                }
                $result = $this->expressionEvaluate($expString, $parameters, $functions);

                if (\is_bool($result)) {
                    if (!$result) {
                        $policyEffects[$i] = Effector::INDETERMINATE;

                        continue;
                    }
                } elseif (\is_float($result)) {
                    if (0 == $result) {
                        $policyEffects[$i] = Effector::INDETERMINATE;

                        continue;
                    } else {
                        $matcherResults[$i] = $result;
                    }
                } else {
                    throw new CasbinException('matcher result should be bool, int or float');
                }
                if (isset($parameters['p_eft'])) {
                    $eft = $parameters['p_eft'];
                    if ('allow' == $eft) {
                        $policyEffects[$i] = Effector::ALLOW;
                    } elseif ('deny' == $eft) {
                        $policyEffects[$i] = Effector::DENY;
                    } else {
                        $policyEffects[$i] = Effector::INDETERMINATE;
                    }
                } else {
                    $policyEffects[$i] = Effector::ALLOW;
                }

                if (isset($this->model->model['e']['e']) && 'priority(p_eft) || deny' == $this->model->model['e']['e']->value) {
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

        $result = $this->eft->mergeEffects($this->model->model['e']['e']->value, $policyEffects, $matcherResults);

        if (Log::getLogger()->isEnabled()) {
            $reqStr = 'Request: ';
            $reqStr .= implode(', ', array_values($rvals));

            $reqStr .= sprintf(' ---> %s', (string) $result);
            Log::logPrint($reqStr);
        }

        return $result;
    }

    protected function expressionEvaluate($expString, $parameters, $functions)
    {
        $expString = preg_replace_callback(
            '/([\s\S]*in\s+)\(([\s\S]+)\)([\s\S]*)/',
            function ($m) {
                return $m[1].'['.$m[2].']'.$m[3];
            },
            $expString
        );

        $expressionLanguage = new ExpressionLanguage();
        foreach ($functions as $key => $func) {
            $expressionLanguage->register($key, function (...$args) use ($key) {
                return sprintf($key.'(%1$s)', implode(',', $args));
            }, function ($arguments, ...$args) use ($func) {
                return $func(...$args);
            });
        }
        $expressionLanguage->evaluate($expString, $parameters);
        // $expressionLanguage->compile($expString, array_keys($parameters));
        return $expressionLanguage->evaluate($expString, $parameters);
    }
}
