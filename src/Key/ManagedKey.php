<?php

declare(strict_types=1);

namespace Comandi\Encryption\Key;

use function Sodium\memzero;

abstract class ManagedKey
{
    /**
     * @var bool
     */
    private $decrypted = false;

    /**
     * @var string
     */
    private $plaintextDataKey;

    /**
     * @var string
     */
    private $encryptedDataKey;

    /**
     * @var KeySpecification
     */
    private $specification;

    private function __construct(KeySpecification $specification, string $encryptedKey, string $plaintextKey = null)
    {
        $this->specification = $specification;

        $this->encryptedDataKey = $encryptedKey;

        if (null !== $plaintextKey) {
            $this->decrypted = true;
            $this->plaintextDataKey = $plaintextKey;
        }
    }

    public function __destruct()
    {
        $this->seal();
    }

    public function isDecrypted()
    {
        return $this->decrypted;
    }

    public function plaintext()
    {
        return $this->plaintextDataKey;
    }

    public function ciphertext()
    {
        return $this->encryptedDataKey;
    }

    public function keyId()
    {
        return $this->specification->keyId();
    }

    public function masterKeyId()
    {
        return $this->specification->masterKeyId();
    }

    public function privateLabel()
    {
        return $this->specification->privateLabel();
    }

    /**
     * Returns a clone of the key, with the plain text
     *
     * @param string $plaintext
     *
     * @return DataKey|PrivateLabelMasterKey
     */
    public function withPlaintext(string $plaintext)
    {
        return new static(
            clone $this->specification,
            $this->encryptedDataKey,
            $plaintext
        );
    }

    public static function createNew(
        string $privateLabel,
        string $keyId,
        string $masterKeyId,
        string $encryptedKey,
        string $plaintextKey
    ) {
        return new static(
            KeySpecification::createNew($privateLabel, $keyId, $masterKeyId),
            $encryptedKey,
            $plaintextKey
        );
    }

    public static function fromArray(array $array)
    {
        return new static(
            KeySpecification::fromArray($array['specification']),
            \hex2bin($array['encryptedDataKey'])
        );
    }

    public function toArray()
    {
        $to_return = [
            'specification' => $this->specification->toArray(),
            'encryptedDataKey' => \bin2hex($this->encryptedDataKey),
        ];

        return $to_return;
    }

    public function toString()
    {
        $key_as_array = \json_encode($this->toArray());

        return \base64_encode($key_as_array);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public static function fromString(string $keyString)
    {
        $key_array = \json_decode(\base64_decode($keyString, true), true);

        return static::fromArray($key_array);
    }

    /**
     * Clear out the plaintext key.
     *
     * This is about the only place in this class
     * that actually modifies the instance.
     */
    public function seal()
    {
        if ($this->isDecrypted()) {
            memzero($this->plaintextDataKey);
            $this->decrypted = false;
        }
    }

    /**
     * Force a deep clone
     */
    public function __clone()
    {
        $this->specification = clone $this->specification;
    }
}
