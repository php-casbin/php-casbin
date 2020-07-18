<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Effect\DefaultEffector;
use Casbin\Effect\Effector;
use Casbin\Exceptions\CasbinException;
use Casbin\Exceptions\InvalidFilePathException;
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
use Casbin\Util\Util;
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
     * @var Adapter|null
     */
    protected $adapter;

    /**
     * Watcher.
     *
     * @var Watcher|null
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
     * $autoNotifyWatcher.
     *
     * @var bool
     */
    protected $autoNotifyWatcher;

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
        $paramLen = \count($params);
        if ($paramLen >= 1) {
            if (\is_bool($enableLog = $params[$paramLen - 1])) {
                $this->enableLog($enableLog);
                ++$parsedParamLen;
            }
        }

        if (2 == $paramLen - $parsedParamLen) {
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
        } elseif (1 == $paramLen - $parsedParamLen) {
            $p0 = $params[0];
            if (\is_string($p0)) {
                $this->initWithFile($p0, '');
            } else {
                $this->initWithModelAndAdapter($p0, null);
            }
        } elseif (0 == $paramLen - $parsedParamLen) {
            // pass
        } else {
            throw new CasbinException('Invalid parameters for enforcer.');
        }
    }

    /**
     * initializes an enforcer with a model file and a policy file.
     *
     * @param string $modelPath
     * @param string $policyPath
     *
     * @throws CasbinException
     */
    public function initWithFile(string $modelPath, string $policyPath): void
    {
        $adapter = new FileAdapter($policyPath);
        $this->initWithAdapter($modelPath, $adapter);
    }

    /**
     * initializes an enforcer with a database adapter.
     *
     * @param string  $modelPath
     * @param Adapter $adapter
     *
     * @throws CasbinException
     */
    public function initWithAdapter(string $modelPath, Adapter $adapter): void
    {
        $m = Model::newModelFromFile($modelPath);
        $this->initWithModelAndAdapter($m, $adapter);

        $this->modelPath = $modelPath;
    }

    /**
     * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     *
     * @param Model        $m
     * @param Adapter|null $adapter
     */
    public function initWithModelAndAdapter(Model $m, Adapter $adapter = null): void
    {
        $this->adapter = $adapter;

        $this->model = $m;
        $this->model->printModel();

        $this->fm = Model::loadFunctionMap();

        $this->initialize();

        // Do not initialize the full policy when using a filtered adapter
        $ok = $this->adapter instanceof FilteredAdapter ? $this->adapter->isFiltered() : false;

        if (!\is_null($this->adapter) && !$ok) {
            $this->loadPolicy();
        }
    }

    /**
     * initializes an enforcer with a database adapter.
     */
    protected function initialize(): void
    {
        $this->rm = new DefaultRoleManager(10);
        $this->eft = new DefaultEffector();
        $this->watcher = null;

        $this->enabled = true;
        $this->autoSave = true;
        $this->autoBuildRoleLinks = true;
        $this->autoNotifyWatcher = true;
    }

    /**
     * reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     *
     * @throws CasbinException
     */
    public function loadModel(): void
    {
        $this->model = Model::newModelFromFile($this->modelPath);
        $this->model->printModel();
        $this->fm = Model::loadFunctionMap();

        $this->initialize();
    }

    /**
     * gets the current model.
     *
     * @return Model
     */
    public function getModel(): Model
    {
        return $this->model;
    }

    /**
     * sets the current model.
     *
     * @param Model $model
     */
    public function setModel(Model $model): void
    {
        $this->model = $model;
        $this->fm = $this->model->loadFunctionMap();

        $this->initialize();
    }

    /**
     * gets the current adapter.
     *
     * @return Adapter
     */
    public function getAdapter(): Adapter
    {
        return $this->adapter;
    }

    /**
     * sets the current adapter.
     *
     * @param Adapter $adapter
     */
    public function setAdapter(Adapter $adapter): void
    {
        $this->adapter = $adapter;
    }

    /**
     * sets the current watcher.
     *
     * @param Watcher $watcher
     */
    public function setWatcher(Watcher $watcher): void
    {
        $this->watcher = $watcher;
        $this->watcher->setUpdateCallback(function () {
            $this->loadPolicy();
        });
    }

    /**
     * gets the current role manager.
     *
     * @return RoleManager
     */
    public function getRoleManager(): RoleManager
    {
        return $this->rm;
    }

    /**
     * sets the current role manager.
     *
     * @param RoleManager $rm
     */
    public function setRoleManager(RoleManager $rm): void
    {
        $this->rm = $rm;
    }

    /**
     * @param string   $name
     * @param \Closure $fn
     */
    public function addMatchingFunc(string $name, \Closure $fn): void
    {
        $this->rm->addMatchingFunc($name, $fn);
    }

    /**
     * @param string   $name
     * @param \Closure $fn
     */
    public function addDomainMatchingFunc(string $name, \Closure $fn): void
    {
        $this->rm->addDomainMatchingFunc($name, $fn);
    }

    /**
     * sets the current effector.
     *
     * @param Effector $eft
     */
    public function setEffector(Effector $eft): void
    {
        $this->eft = $eft;
    }

    /**
     * clears all policy.
     */
    public function clearPolicy(): void
    {
        $this->model->clearPolicy();
    }

    /**
     * reloads the policy from file/database.
     */
    public function loadPolicy(): void
    {
        $this->model->clearPolicy();

        try {
            $this->adapter->loadPolicy($this->model);
        } catch (InvalidFilePathException $e) {
            //throw $e;
        }

        $this->model->printPolicy();
        if ($this->autoBuildRoleLinks) {
            $this->buildRoleLinks();
        }
    }

    /**
     * reloads a filtered policy from file/database.
     *
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function loadFilteredPolicy($filter): void
    {
        $this->model->clearPolicy();

        if ($this->adapter instanceof FilteredAdapter) {
            $filteredAdapter = $this->adapter;
            $filteredAdapter->loadFilteredPolicy($this->model, $filter);
        } else {
            throw new CasbinException('filtered policies are not supported by this adapter');
        }

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
    public function isFiltered(): bool
    {
        if (!$this->adapter instanceof FilteredAdapter) {
            return false;
        }

        $filteredAdapter = $this->adapter;

        return $filteredAdapter->isFiltered();
    }

    /**
     * saves the current policy (usually after changed with Casbin API) back to file/database.
     *
     * @return mixed
     *
     * @throws CasbinException
     */
    public function savePolicy(): void
    {
        if ($this->isFiltered()) {
            throw new CasbinException('cannot save a filtered policy');
        }

        $this->adapter->savePolicy($this->model);

        if (null !== $this->watcher) {
            $this->watcher->update();
        }
    }

    /**
     * changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
     *
     * @param bool $enabled
     */
    public function enableEnforce(bool $enabled = true): void
    {
        $this->enabled = $enabled;
    }

    /**
     * changes whether Casbin will log messages to the Logger.
     *
     * @param bool $enabled
     */
    public function enableLog(bool $enabled = true): void
    {
        Log::getLogger()->enableLog($enabled);
    }

    /**
     * controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
     *
     * @param bool $enabled
     */
    public function EnableAutoNotifyWatcher(bool $enabled = true): void
    {
        $this->autoNotifyWatcher = $enabled;
    }

    /**
     * controls whether to save a policy rule automatically to the adapter when it is added or removed.
     *
     * @param bool $autoSave
     */
    public function enableAutoSave(bool $autoSave = true): void
    {
        $this->autoSave = $autoSave;
    }

    /**
     * controls whether to rebuild the role inheritance relations when a role is added or deleted.
     *
     * @param bool $autoBuildRoleLinks
     */
    public function enableAutoBuildRoleLinks(bool $autoBuildRoleLinks = true): void
    {
        $this->autoBuildRoleLinks = $autoBuildRoleLinks;
    }

    /**
     * manually rebuild the role inheritance relations.
     */
    public function buildRoleLinks(): void
    {
        $this->rm->clear();
        $this->model->buildRoleLinks($this->rm);
    }

    /**
     * use a custom matcher to decides whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
     *
     * @param string $matcher
     * @param mixed  ...$rvals
     *
     * @return bool|mixed
     *
     * @throws CasbinException
     */
    protected function enforcing(string $matcher, ...$rvals): bool
    {
        if (!$this->enabled) {
            return true;
        }

        $functions = $this->fm->getFunctions();

        if (isset($this->model['g'])) {
            foreach ($this->model['g'] as $key => $ast) {
                $rm = $ast->rM;
                $functions[$key] = BuiltinOperations::generateGFunction($rm);
            }
        }

        if (!isset($this->model['m']['m'])) {
            throw new CasbinException('model is undefined');
        }

        $expString = '';
        if ('' === $matcher) {
            $expString = $this->getExpString($this->model['m']['m']->value);
        } else {
            $expString = Util::removeComments(Util::escapeAssertion($matcher));
        }

        $rTokens = array_values($this->model['r']['r']->tokens);
        $pTokens = array_values($this->model['p']['p']->tokens);

        $rParameters = array_combine($rTokens, $rvals);

        if (false === $rParameters) {
            throw new CasbinException('invalid request size');
        }

        $expressionLanguage = $this->getExpressionLanguage($functions);
        $expression = new ExpressionLanguage();
        $hasEval = Util::hasEval($expString);

        if (!$hasEval) {
            $expressionLanguage = $this->getExpressionLanguage($functions);
            $expression = $expressionLanguage->parse($expString, array_merge($rTokens, $pTokens));
        }

        $policyEffects = [];
        $matcherResults = [];

        $policyLen = \count($this->model['p']['p']->policy);

        if (0 != $policyLen) {
            foreach ($this->model['p']['p']->policy as $i => $pvals) {
                $parameters = array_combine($pTokens, $pvals);
                if (false === $parameters) {
                    throw new CasbinException('invalid policy size');
                }

                if ($hasEval) {
                    $ruleNames = Util::getEvalValue($expString);
                    $expWithRule = $expString;
                    $pTokens_flipped = array_flip($pTokens);
                    foreach ($ruleNames as $ruleName) {
                        if (isset($pTokens_flipped[$ruleName])) {
                            $rule = Util::escapeAssertion($pvals[$pTokens_flipped[$ruleName]]);
                            $expWithRule = Util::replaceEval($expWithRule, $rule);
                        } else {
                            throw new CasbinException('please make sure rule exists in policy when using eval() in matcher');
                        }

                        $expressionLanguage = $this->getExpressionLanguage($functions);
                        $expression = $expressionLanguage->parse($expWithRule, array_merge($rTokens, $pTokens));
                    }
                }

                $parameters = array_merge($rParameters, $parameters);
                $result = $expressionLanguage->evaluate($expression, $parameters);

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

                if (isset($this->model['e']['e']) && 'priority(p_eft) || deny' == $this->model['e']['e']->value) {
                    break;
                }
            }
        } else {
            $parameters = $rParameters;
            foreach ($this->model['p']['p']->tokens as $token) {
                $parameters[$token] = '';
            }

            $result = $expressionLanguage->evaluate($expression, $parameters);

            if ($result) {
                $policyEffects[0] = Effector::ALLOW;
            } else {
                $policyEffects[0] = Effector::INDETERMINATE;
            }
        }

        $result = $this->eft->mergeEffects($this->model['e']['e']->value, $policyEffects, $matcherResults);

        if (Log::getLogger()->isEnabled()) {
            $reqStr = 'Request: ';
            $reqStr .= implode(', ', array_values($rvals));

            $reqStr .= sprintf(' ---> %s', (string) $result);
            Log::logPrint($reqStr);
        }

        return $result;
    }

    /**
     * @param array $functions
     *
     * @return ExpressionLanguage
     */
    protected function getExpressionLanguage(array $functions): ExpressionLanguage
    {
        $expressionLanguage = new ExpressionLanguage();
        foreach ($functions as $key => $func) {
            $expressionLanguage->register($key, function (...$args) use ($key) {
                return sprintf($key.'(%1$s)', implode(',', $args));
            }, function ($arguments, ...$args) use ($func) {
                return $func(...$args);
            });
        }

        return $expressionLanguage;
    }

    /**
     * @param string $expString
     *
     * @return string
     */
    protected function getExpString(string $expString): string
    {
        return preg_replace_callback(
            '/([\s\S]*in\s+)\(([\s\S]+)\)([\s\S]*)/',
            function ($m) {
                return $m[1].'['.$m[2].']'.$m[3];
            },
            $expString
        );
    }

    /**
     * decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param mixed ...$rvals
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforce(...$rvals): bool
    {
        return $this->enforcing('', ...$rvals);
    }

    /**
     * use a custom matcher to decides whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
     *
     * @param string $matcher
     * @param mixed  ...$rvals
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforceWithMatcher(string $matcher, ...$rvals): bool
    {
        return $this->enforcing($matcher, ...$rvals);
    }
}
