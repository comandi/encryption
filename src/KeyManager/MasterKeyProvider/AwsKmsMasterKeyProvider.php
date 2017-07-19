<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

use Aws\Kms\KmsClient;
use Comandi\Encryption\Key\PrivateLabelMasterKey;

final class AwsKmsMasterKeyProvider implements MasterKeyProvider
{
    /**
     * @var KmsClient
     */
    private $kmsClient;
    /**
     * @var AwsKmsOptions
     */
    private $kmsOptions;

    public function __construct(KmsClient $kmsClient, AwsKmsOptions $kmsOptions)
    {
        $this->kmsClient = $kmsClient;
        $this->kmsOptions = $kmsOptions;
    }

    public static function providerName(): string
    {
        return 'AWS-KMS';
    }

    public function generateMasterKeyForPrivateLabel(int $keyLengthInBytes, string $privateLabel, string $keyId): PrivateLabelMasterKey
    {
        // Retrieve a new data key from KMS
        $kms_key = $this->kmsClient->generateDataKey([
            'KeyId' => $this->kmsOptions->keyId(),
            'NumberOfBytes' => $keyLengthInBytes,
        ]);

        // Wrap the key in our own key.
        $master_key = PrivateLabelMasterKey::createNew(
            $privateLabel,
            $keyId,
            'kms:'.$kms_key['KeyId'],
            $kms_key['CiphertextBlob'],
            $kms_key['Plaintext']
        );

        return $master_key;
    }

    public function decryptMasterKey(PrivateLabelMasterKey $key): PrivateLabelMasterKey
    {
        if ($key->isDecrypted()) {
            return $key;
        }

        $kms_response = $this->kmsClient->decrypt([
            'CiphertextBlob' => $key->ciphertext(),
        ]);

        if ($kms_response['KeyId'] !== substr($key->masterKeyId(), 4)) {
            // Something fishy happened!
            throw new \LogicException('Master key decrypted with unexpected KMS key...');
        }

        return $key->withPlaintext($kms_response['Plaintext']);
    }

    public function acceptsMasterKey(PrivateLabelMasterKey $key): bool
    {
        return substr($key->masterKeyId(), 0,4) === 'kms:';
    }
}
