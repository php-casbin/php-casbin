<?php

declare(strict_types=1);

namespace Casbin\Model;

use Casbin\Config\Config;
use Casbin\Config\ConfigContract;
use Casbin\Constant\Constants;
use Casbin\Exceptions\CasbinException;
use Casbin\Log\Logger\DefaultLogger;
use Casbin\Util\Util;

/**
 * Class Model.
 * Represents the whole access control model.
 *
 * @package Casbin\Model
 * @author techlee@qq.com
 */
class Model extends Policy
{
    const DEFAULT_DOMAIN = '';
    const DEFAULT_SEPARATOR = '::';

    /**
     * @var array<string, string>
     */
    protected array $sectionNameMap = [
        'r' => 'request_definition',
        'p' => 'policy_definition',
        'g' => 'role_definition',
        'e' => 'policy_effect',
        'm' => 'matchers',
    ];

    public function __construct()
    {
        $this->setLogger(new DefaultLogger());
    }

    public function __clone()
    {
        $this->sectionNameMap = $this->sectionNameMap;
        $newAstMap = [];
        foreach ($this->items as $ptype => $ast) {
            foreach ($ast as $i => $v) {
                $newAstMap[$ptype][$i] = clone $v;
            }
        }
        $this->items = $newAstMap;
    }

    /**
     * @param ConfigContract $cfg
     * @param string $sec
     * @param string $key
     *
     * @return bool
     * @throws CasbinException
     */
    private function loadAssertion(ConfigContract $cfg, string $sec, string $key): bool
    {
        $value = $cfg->getString($this->sectionNameMap[$sec] . '::' . $key);

        return $this->addDef($sec, $key, $value);
    }

    /**
     * Adds an assertion to the model.
     *
     * @param string $sec
     * @param string $key
     * @param string $value
     *
     * @return bool
     * @throws CasbinException
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
            $ast->tokens = explode(',', $ast->value);
            foreach ($ast->tokens as $i => $token) {
                $ast->tokens[$i] = $key . '_' . trim($token);
            }
        } else if ('g' == $sec) {
            $ast->tokens = explode(',', $ast->value);
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

        return (string)$i;
    }

    /**
     * @param ConfigContract $cfg
     * @param string $sec
     * @throws CasbinException
     */
    private function loadSection(ConfigContract $cfg, string $sec): void
    {
        $i = 1;
        for (;;) {
            if (!$this->loadAssertion($cfg, $sec, $sec . $this->getKeySuffix($i))) {
                break;
            } else {
                ++$i;
            }
        }
    }

    /**
     * Creates an empty model.
     *
     * @return Model
     */
    public static function newModel(): self
    {
        return new self();
    }

    /**
     * Creates a model from a .CONF file.
     *
     * @param string $path
     *
     * @return Model
     * @throws CasbinException
     */
    public static function newModelFromFile(string $path): self
    {
        $m = self::newModel();

        $m->loadModel($path);

        return $m;
    }

    /**
     * Creates a model from a string which contains model text.
     *
     * @param string $text
     *
     * @return Model
     * @throws CasbinException
     */
    public static function newModelFromString(string $text): self
    {
        $m = self::newModel();

        $m->loadModelFromText($text);

        return $m;
    }

    /**
     * Loads the model from model CONF file.
     *
     * @param string $path
     * @throws CasbinException
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
     * Loads the model from the text.
     *
     * @param string $text
     * @throws CasbinException
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
     * Prints the model to the log.
     */
    public function printModel(): void
    {
        if (!$this->getLogger()->isEnabled()) {
            return;
        }

        $modelInfo = [];
        foreach ($this->items as $sec => $astMap) {
            foreach ($astMap as $key => $ast) {
                $modelInfo[] = [$sec, $key, $ast->value];
            }
        }

        $this->getLogger()->logModel($modelInfo);
    }

    /**
     * Loads an initial function map.
     *
     * @return FunctionMap
     */
    public static function loadFunctionMap(): FunctionMap
    {
        return FunctionMap::loadFunctionMap();
    }

    public function getNameWithDomain(string $domain, string $name): string
    {
        return $domain . self::DEFAULT_SEPARATOR . $name;
    }

    public function getSubjectHierarchyMap(array $policies): array
    {
        $subjectHierarchyMap = [];
        // Tree structure of role
        $policyMap = [];
        foreach ($policies as $policy) {
            if (count($policy) < 2) {
                throw new CasbinException('policy g expect 2 more params');
            }
            $domain = self::DEFAULT_DOMAIN;
            if (count($policy) != 2) {
                $domain = $policy[2];
            }
            $child = $this->getNameWithDomain($domain, $policy[0]);
            $parent = $this->getNameWithDomain($domain, $policy[1]);
            $policyMap[$parent][] = $child;
            if (!isset($subjectHierarchyMap[$child])) {
                $subjectHierarchyMap[$child] = 0;
            }
            if (!isset($subjectHierarchyMap[$parent])) {
                $subjectHierarchyMap[$parent] = 0;
            }
            $subjectHierarchyMap[$child] = 1;
        }
        // Use queues for levelOrder
        $queue = [];
        foreach ($subjectHierarchyMap as $k => $v) {
            $root = $k;
            if ($v != 0) {
                continue;
            }
            $lv = 0;
            $queue[] = $root;
            while (count($queue) != 0) {
                $sz = count($queue);
                for ($i = 0; $i < $sz; $i++) {
                    $node = $queue[array_key_first($queue)];
                    unset($queue[array_key_first($queue)]);

                    $nodeValue = $node;
                    $subjectHierarchyMap[$nodeValue] = $lv;
                    if (isset($policyMap[$nodeValue])) {
                        foreach ($policyMap[$nodeValue] as $child) {
                            $queue[] = $child;
                        }
                    }
                }
                $lv++;
            }
        }

        return $subjectHierarchyMap;
    }

    public function sortPoliciesBySubjectHierarchy(): void
    {
        if ($this->items['e']['e']->value != Constants::SUBJECT_PRIORITY_EFFECT) {
            return;
        }
        $subIndex = 0;

        foreach ($this->items['p'] as $ptype => $assertion) {
            try {
                $domainIndex = $this->getFieldIndex($ptype, Constants::DOMAIN_INDEX);
            } catch (CasbinException) {
                $domainIndex = -1;
            }
            $policies = &$assertion->policy;
            $subjectHierarchyMap = $this->getSubjectHierarchyMap($this->items['g']['g']->policy);

            usort($policies, function ($i, $j) use ($subIndex, $domainIndex, $subjectHierarchyMap): int {
                $domain1 = self::DEFAULT_DOMAIN;
                $domain2 = self::DEFAULT_DOMAIN;
                if ($domainIndex != -1) {
                    $domain1 = $i[$domainIndex];
                    $domain2 = $j[$domainIndex];
                }
                $name1 = $this->getNameWithDomain($domain1, $i[$subIndex]);
                $name2 = $this->getNameWithDomain($domain2, $j[$subIndex]);

                $p1 = $subjectHierarchyMap[$name1] ?? 0;
                $p2 = $subjectHierarchyMap[$name2] ?? 0;

                if ($p1 == $p2) {
                    return 0;
                }
                return ($p1 > $p2) ? -1 : 1;
            });

            foreach ($assertion->policy as $i => $policy) {
                $assertion->policyMap[implode(',', $policy)] = $i;
            }
        }
    }

    public function sortPoliciesByPriority(): void
    {
        foreach ($this->items['p'] as $ptype => $assertion) {
            try {
                $priorityIndex = $this->getFieldIndex($ptype, Constants::PRIORITY_INDEX);
            } catch (CasbinException) {
                continue;
            }
            $policies = &$assertion->policy;
            usort($policies, function ($i, $j) use ($priorityIndex): int {
                $p1 = $i[$priorityIndex];
                $p2 = $j[$priorityIndex];
                if ($p1 == $p2) {
                    return 0;
                }
                return ($p1 < $p2) ? -1 : 1;
            });
            foreach ($assertion->policy as $i => $policy) {
                $assertion->policyMap[implode(',', $policy)] = $i;
            }
        }
    }
}
