<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

class HashicorpVaultOptions
{
    /**
     * @var string
     */
    private $backendUrl;

    /**
     * @var string
     */
    private $token;

    /**
     * @var string
     */
    private $keyName;

    /**
     * Options for Hashicorp Vault Master Key Provider
     *
     * @param string $backendUrl The URL to the transit mount
     * @param string $token      Authentication token for Vault
     * @param string $keyName    Transit backend key name to use
     */
    public function __construct(string $backendUrl, string $token, string $keyName)
    {

        $this->backendUrl = $backendUrl;
        $this->token = $token;
        $this->keyName = $keyName;
    }

    /**
     * @return string
     */
    public function backendUrl(): string
    {
        return $this->backendUrl;
    }

    /**
     * @return string
     */
    public function token(): string
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function keyName(): string
    {
        return $this->keyName;
    }
}