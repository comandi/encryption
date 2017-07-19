<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

use Comandi\Encryption\Key\PrivateLabelMasterKey;

interface MasterKeyProvider
{
    /**
     * Returns the name of the key provider.
     *
     * @return string
     */
    public static function providerName(): string;

    /**
     * Generate a Private Label Master Key for the given private label.
     */
    public function generateMasterKeyForPrivateLabel(
        int $keyLengthInBytes,
        string $privateLabel,
        string $keyId
    ): PrivateLabelMasterKey;

    public function decryptMasterKey(PrivateLabelMasterKey $key): PrivateLabelMasterKey;

    /**
     * Whether this provider will accept the given Master Key.
     */
    public function acceptsMasterKey(PrivateLabelMasterKey $key): bool;
}
