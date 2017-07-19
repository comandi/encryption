<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

use Comandi\Encryption\Exception\MasterKeyDoesNotExist;
use Comandi\Encryption\Key\PrivateLabelMasterKey;
use const Sodium\CRYPTO_SECRETBOX_NONCEBYTES;
use function Sodium\crypto_secretbox;
use function Sodium\crypto_secretbox_open;

/**
 * InMemoryMasterKeyProvider
 *
 * The InMemoryMasterKeyProvider is STRICTLY FOR TESTING AND
 * NON-PRODUCTION USE.
 *
 * It keeps all Master Keys in memory, and they are therefore
 * thrown away as soon as the object is destroyed.
 */
final class InMemoryMasterKeyProvider implements MasterKeyProvider
{
    /**
     * Contains a list of Master Keys.
     *
     * @var string
     */
    private $privateKey;

    /**
     * @param null|string $privateKey Allows overriding of Master Key. Must be 32 bytes.
     */
    public function __construct(string $privateKey = null)
    {
        if (null === $privateKey) {
            $this->privateKey = \random_bytes(32);
            return;
        }

        if (32 !== mb_strlen($privateKey, '8bit')) {
            throw new \InvalidArgumentException('The master key must be 32 bytes.');
        }

        $this->privateKey = $privateKey;
    }

    /**
     * Returns the name of the key provider.
     *
     * @return string
     */
    public static function providerName(): string
    {
        return 'In-Memory';
    }

    public function generateMasterKeyForPrivateLabel(
        int $keyLengthInBytes,
        string $privateLabel,
        string $keyId
    ): PrivateLabelMasterKey
    {
        $plaintext = random_bytes($keyLengthInBytes);
        $nonce = random_bytes(CRYPTO_SECRETBOX_NONCEBYTES);

        $ciphertext = sprintf(
            '%s::%s',
            $nonce,
            crypto_secretbox($plaintext, $nonce, $this->privateKey)
        );

        return PrivateLabelMasterKey::createNew(
            $privateLabel,
            $keyId,
            'imkp:0',
            $ciphertext,
            $plaintext
        );
    }

    public function decryptMasterKey(PrivateLabelMasterKey $key): PrivateLabelMasterKey
    {
        if ($key->isDecrypted()) {
            return $key;
        }

        if (!$this->acceptsMasterKey($key)) {
            throw MasterKeyDoesNotExist::create($key->masterKeyId());
        }

        list($nonce, $ciphertext) = explode('::', $key->ciphertext(), 2);

        $plaintext = crypto_secretbox_open($ciphertext, $nonce, $this->privateKey);

        return $key->withPlaintext($plaintext);
    }

    public function acceptsMasterKey(PrivateLabelMasterKey $key): bool
    {
        return 'imkp:0' === $key->masterKeyId();
    }
}
