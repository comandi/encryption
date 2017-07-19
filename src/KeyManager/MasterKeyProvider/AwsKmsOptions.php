<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

class AwsKmsOptions
{
    /**
     * @var string
     */
    private $keyId;

    public function __construct(string $keyId)
    {
        $this->keyId = $keyId;
    }

    public function keyId(): string
    {
        return $this->keyId;
    }
}
