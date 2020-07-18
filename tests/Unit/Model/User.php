<?php

namespace Casbin\Tests\Unit\Model;

class User
{
    /**
     * @var string
     */
    public $Name;

    /**
     * @var int
     */
    public $Age;

    public function __construct(string $Name, int $Age)
    {
        $this->Name = $Name;
        $this->Age = $Age;
    }
}
