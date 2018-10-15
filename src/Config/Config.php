<?php
namespace Casbin\Config;

use Casbin\Exceptions\CasbinException;

class Config implements ConfigContract
{
    const DEFAULT_SECTION = 'default';

    const DEFAULT_COMMENT = '#';

    const DEFAULT_COMMENT_SEM = ';';

    const DEFAULT_MULTI_LINE_SEPARATOR = '\\';

    public $data = [];

    public static function newConfig($confName)
    {
        $c = new self();
        $c->parse($confName);
        return $c;
    }

    public function addConfig($section, $option, $value)
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

    private function parse($fname)
    {

        $buf = fopen($fname, 'r');

        $res = $this->parseBuffer($buf);

        fclose($buf);

        return $res;
    }

    private function parseBuffer($buf)
    {
        $section = null;
        $lineNum = 0;

        while ($line = fgets($buf)) {
            $lineNum++;

            $line = trim($line);
            if (!$line) {
                continue;
            }

            if (substr($line, 0, 1) == self::DEFAULT_COMMENT) {
                continue;
            } elseif (substr($line, 0, 1) == self::DEFAULT_COMMENT_SEM) {
                continue;
            } elseif (substr($line, 0, 1) == '[' && substr($line, -1) == ']') {
                $section = substr($line, 1, -1);
            } else {
                $this->write($section, $lineNum, $line);
            }
        }
        return true;
    }

    private function write($section, $lineNum, $lineContent)
    {
        if (empty($lineContent)) {
            return;
        }
        $optionVal = explode('=', $lineContent, 2);
        if (count($optionVal) != 2) {
            throw new CasbinException(sprintf("parse the content error : line %d , %s = ?", $lineNum, $optionVal));
        }

        $option = trim($optionVal[0]);
        $value  = trim($optionVal[1]);

        $this->addConfig($section, $option, $value);

        return;
    }

    public function getString($key)
    {
        return $this->get($key);
    }

    public function get($key)
    {
        $keys = explode('::', $key);
        if (count($keys) >= 2) {
            $section = $keys[0];
            $option  = $keys[1];
        } else {
            $section = self::DEFAULT_SECTION;
            $option  = $keys[0];
        }

        return isset($this->data[$section][$option]) ? $this->data[$section][$option] : '';
    }
}
