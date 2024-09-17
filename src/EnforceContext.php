<?php

declare(strict_types=1);

namespace Casbin;

/**
 * Class EnforceContext
 * EnforceContext is used as the first element of the parameter "rvals" in method "enforce"
 *
 * @author ab1652759879@gmail.com
 */
class EnforceContext
{
    /**
     * rType
     *
     * @var string
     */
    public string $rType;
    /**
     * pType
     *
     * @var string
     */
    public string $pType;
    /**
     * eType
     *
     * @var string
     */
    public string $eType;
    /**
     * mType
     *
     * @var string
     */
    public string $mType;

    /**
     * Create a default structure based on the suffix
     *
     * @param string $suffix
     */
    public function __construct(string $suffix)
    {
        $this->rType = "r" . $suffix;
        $this->pType = "p" . $suffix;
        $this->eType = "e" . $suffix;
        $this->mType = "m" . $suffix;
    }
}
