<?php

declare(strict_types=1);

namespace Casbin\Config;

use Casbin\Exceptions\CasbinException;

/**
 * Class Config.
 *
 * @author techlee@qq.com
 */
final class Config implements ConfigContract
{
    const DEFAULT_SECTION = 'default';

    const DEFAULT_COMMENT = '#';

    const DEFAULT_COMMENT_SEM = ';';

    const DEFAULT_MULTI_LINE_SEPARATOR = '\\';

    /**
     * @var array<string, array<string, string>>
     */
    public $data = [];

    /**
     * Create an empty configuration representation from file.
     *
     * @param string $confName
     *
     * @return ConfigContract
     * @throws CasbinException
     */
    public static function newConfig(string $confName): ConfigContract
    {
        $c = new static();
        $c->parse($confName);

        return $c;
    }

    /**
     * Create an empty configuration representation from text.
     *
     * @param string $text
     *
     * @return ConfigContract
     * @throws CasbinException
     */
    public static function newConfigFromText(string $text): ConfigContract
    {
        $c = new Config();
        $c->parseBuffer($text);

        return $c;
    }

    /**
     * Adds a new section->key:value to the configuration.
     *
     * @param string $section
     * @param string $option
     * @param string $value
     *
     * @return bool
     */
    public function addConfig(string $section, string $option, string $value): bool
    {
        if (empty($section)) {
            $section = self::DEFAULT_SECTION;
        }

        if (!isset($this->data[$section])) {
            $this->data[$section] = [];
        }

        $this->data[$section][$option] = $value;

        return true;
    }

    /**
     * @param string $fname
     *
     * @return bool
     *
     * @throws CasbinException
     */
    private function parse(string $fname): bool
    {
        $buf = file_get_contents($fname);

        return $buf === false ? false : $this->parseBuffer($buf);
    }

    /**
     * @param string $buf
     *
     * @return bool
     *
     * @throws CasbinException
     */
    private function parseBuffer(string $buf): bool
    {
        $section = '';
        $lineNum = 0;
        $buffer = '';
        $canWrite = null;

        $buf = preg_replace('/[\r\n]+/', PHP_EOL, $buf);
        $buf = explode(PHP_EOL, $buf == null ? "" : $buf);

        for ($i = 0, $len = \count($buf); $i <= $len; ++$i) {
            if ($canWrite) {
                $this->write($section, $lineNum, $buffer);
                $canWrite = false;
            }

            ++$lineNum;
            $line = isset($buf[$i]) ? $buf[$i] : '';
            if ($i == \count($buf)) {
                if (\strlen($buffer) > 0) {
                    $this->write($section, $lineNum, $buffer);
                }

                break;
            }
            $line = trim($line);

            if ('' == $line || self::DEFAULT_COMMENT == substr($line, 0, 1) || self::DEFAULT_COMMENT_SEM == substr($line, 0, 1)) {
                $canWrite = true;

                continue;
            } elseif ('[' == substr($line, 0, 1) && ']' == substr($line, -1)) {
                if (\strlen($buffer) > 0) {
                    $this->write($section, $lineNum, $buffer);
                    $canWrite = false;
                }
                $section = substr($line, 1, -1);
            } else {
                $p = '';
                if (self::DEFAULT_MULTI_LINE_SEPARATOR == substr($line, -1)) {
                    $p = trim(substr($line, 0, -1));
                } else {
                    $p = $line;
                    $canWrite = true;
                }
                $buffer .= $p;
            }
        }

        return true;
    }

    /**
     * @param string $section
     * @param int $lineNum
     * @param string $b
     *
     * @throws CasbinException
     */
    private function write(string $section, int $lineNum, string &$b): void
    {
        if (\strlen($b) <= 0) {
            return;
        }

        $optionVal = explode('=', $b, 2);

        if (2 != \count($optionVal)) {
            throw new CasbinException(sprintf('parse the content error : line %d , %s = ?', $lineNum, current($optionVal)));
        }

        $option = trim($optionVal[0]);
        $value = trim($optionVal[1]);

        $this->addConfig($section, $option, $value);

        $b = '';
    }

    /**
     * Lookups up the value using the provided key and converts the value to a string.
     *
     * @param string $key
     *
     * @return string
     */
    public function getString(string $key): string
    {
        return $this->get($key);
    }

    /**
     * Lookups up the value using the provided key and converts the value to an array of string
     * by splitting the string by comma.
     *
     * @param string $key
     *
     * @return array
     */
    public function getStrings(string $key): array
    {
        $v = $this->get($key);
        if ('' == $v) {
            return [];
        }

        return explode(',', $v);
    }

    /**
     * Sets the value for the specific key in the Config.
     *
     * @param string $key
     * @param string $value
     *
     * @throws CasbinException
     */
    public function set(string $key, string $value): void
    {
        if (0 == \strlen($key)) {
            throw new CasbinException('key is empty');
        }

        $section = '';

        $keys = explode('::', strtolower($key));
        if (\count($keys) >= 2) {
            $section = $keys[0];
            $option = $keys[1];
        } else {
            $option = $keys[0];
        }
        $this->addConfig($section, $option, $value);
    }

    /**
     * section.key or key.
     *
     * @param string $key
     *
     * @return string
     */
    public function get(string $key): string
    {
        $keys = explode('::', $key);
        if (\count($keys) >= 2) {
            $section = $keys[0];
            $option = $keys[1];
        } else {
            $section = self::DEFAULT_SECTION;
            $option = $keys[0];
        }

        return isset($this->data[$section][$option]) ? $this->data[$section][$option] : '';
    }
}
