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
 * Class Enforcer
 * the main interface for authorization enforcement and policy management.
 *
 * @author techlee@qq.com
 */
class Enforcer
{
    use InternalApi;
    use ManagementApi;
    use RbacApi;

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
     * Enforcer constructor.
     * Creates an enforcer via file or DB.
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
     * @param mixed ...$params
     *
     * @throws CasbinException
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
     * @param $modelPath
     * @param $policyPath
     *
     * @throws CasbinException
     */
    public function initWithFile($modelPath, $policyPath)
    {
        $adapter = new FileAdapter($policyPath);
        $this->initWithAdapter($modelPath, $adapter);
    }

    /**
     * initializes an enforcer with a database adapter.
     *
     * @param $modelPath
     * @param Adapter $adapter
     *
     * @throws CasbinException
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

    /**
     * initializes an enforcer with a database adapter.
     */
    protected function initialize()
    {
        $this->rm = new DefaultRoleManager(10);
        $this->eft = new DefaultEffector();
        $this->watcher = null;

        $this->enabled = true;
        $this->autoSave = true;
        $this->autoBuildRoleLinks = true;
    }

    /**
     * creates a model.
     *
     * @param mixed ...$text
     *
     * @return Model
     *
     * @throws CasbinException
     */
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

    /**
     * reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     *
     * @throws CasbinException
     */
    public function loadModel()
    {
        $this->model = self::newModel();
        $this->model->loadModel($this->modelPath);
        $this->model->printModel();
        $this->fm = Model::LoadFunctionMap();
    }

    /**
     * gets the current model.
     *
     * @return Model
     */
    public function getModel()
    {
        return $this->model;
    }

    /**
     * sets the current model.
     *
     * @param Model $model
     */
    public function setModel(Model $model)
    {
        $this->model = $model;
        $this->fm = $this->model->loadFunctionMap();
    }

    /**
     * gets the current adapter.
     *
     * @return Adapter
     */
    public function getAdapter()
    {
        return $this->adapter;
    }

    /**
     * sets the current adapter.
     *
     * @param Adapter $adapter
     */
    public function setAdapter(Adapter $adapter)
    {
        $this->adapter = $adapter;
    }

    /**
     * sets the current watcher.
     *
     * @param Watcher $watcher
     */
    public function setWatcher(Watcher $watcher)
    {
        $this->watcher = $watcher;
        $this->watcher->setUpdateCallback(function () {
            $this->loadPolicy();
        });
    }

    /**
     * sets the current role manager.
     *
     * @param RoleManager $rm
     */
    public function setRoleManager(RoleManager $rm)
    {
        $this->rm = $rm;
    }

    /**
     * sets the current effector.
     *
     * @param Effector $eft
     */
    public function setEffector(Effector $eft)
    {
        $this->eft = $eft;
    }

    /**
     * clears all policy.
     */
    public function clearPolicy()
    {
        $this->model->clearPolicy();
    }

    /**
     * reloads the policy from file/database.
     */
    public function loadPolicy()
    {
        $this->model->clearPolicy();
        $this->adapter->loadPolicy($this->model);

        $this->model->printPolicy();
        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }
    }

    /**
     * reloads a filtered policy from file/database.
     *
     * @param $filter
     *
     * @throws CasbinException
     */
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

    /**
     * returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered()
    {
        if (!$this->adapter instanceof FilteredAdapter) {
            return false;
        }

        $filteredAdapter = $this->adapter;
        $filteredAdapter->isFiltered();
    }

    /**
     * saves the current policy (usually after changed with Casbin API) back to file/database.
     *
     * @return mixed
     *
     * @throws CasbinException
     */
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

    /**
     * changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
     *
     * @param bool $enabled
     */
    public function enableEnforce($enabled = true)
    {
        $this->enabled = $enabled;
    }

    /**
     * changes whether Casbin will log messages to the Logger.
     *
     * @param bool $enabled
     */
    public function enableLog($enabled = true)
    {
        Log::getLogger()->enableLog($enabled);
    }

    /**
     * controls whether to save a policy rule automatically to the adapter when it is added or removed.
     *
     * @param bool $autoSave
     */
    public function enableAutoSave($autoSave = true)
    {
        $this->autoSave = $autoSave;
    }

    /**
     * controls whether to rebuild the role inheritance relations when a role is added or deleted.
     *
     * @param bool $autoBuildRoleLinks
     */
    public function enableAutoBuildRoleLinks($autoBuildRoleLinks = true)
    {
        $this->autoBuildRoleLinks = $autoBuildRoleLinks;
    }

    /**
     * manually rebuild the role inheritance relations.
     */
    public function buildRoleLinks()
    {
        $this->rm->clear();
        $this->model->buildRoleLinks($this->rm);
    }

    /**
     * decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param mixed ...$rvals
     *
     * @return bool|mixed
     *
     * @throws CasbinException
     */
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

    /**
     * @param $expString
     * @param $parameters
     * @param $functions
     *
     * @return mixed
     */
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
        // $expressionLanguage->compile($expString, array_keys($parameters));
        return $expressionLanguage->evaluate($expString, $parameters);
    }
}
