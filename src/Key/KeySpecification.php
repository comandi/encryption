<?php

declare(strict_types=1);

namespace Comandi\Encryption\Key;

final class KeySpecification
{
    /**
     * @var string
     */
    private $privateLabel;
    /**
     * @var string
     */
    private $keyId;
    /**
     * @var string
     */
    private $masterKeyId;

    private function __construct(string $privateLabel, string $keyId, string $masterKeyId)
    {
        $this->privateLabel = $privateLabel;
        $this->keyId = $keyId;
        $this->masterKeyId = $masterKeyId;
    }

    /**
     * @return string
     */
    public function privateLabel(): string
    {
        return $this->privateLabel;
    }

    /**
     * @return string
     */
    public function keyId(): string
    {
        return $this->keyId;
    }

    /**
     * @return string
     */
    public function masterKeyId(): string
    {
        return $this->masterKeyId;
    }

    public function toArray(): array
    {
        $to_return = [
            'privateLabel' => $this->privateLabel,
            'keyId' => $this->keyId,
            'masterKeyId' => $this->masterKeyId,
        ];

        return $to_return;
    }

    public static function createNew(string $privateLabel, string $keyId, string $masterKeyId): KeySpecification
    {
        return new self(
            $privateLabel,
            $keyId,
            $masterKeyId
        );
    }

    /**
     * Returns the specification from a previously stored string.
     *
     * @param array $array
     *
     * @return KeySpecification
     */
    public static function fromArray(array $array): self
    {
        return new self(
            $array['privateLabel'],
            $array['keyId'],
            $array['masterKeyId']
        );
    }
}
