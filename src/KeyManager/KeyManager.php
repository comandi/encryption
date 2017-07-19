<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager;

use Comandi\Encryption\EncryptionHelper;
use Comandi\Encryption\Exception\KeyDoesNotExist;
use Comandi\Encryption\Exception\PrivateLabelDoesNotExist;
use Comandi\Encryption\Key\DataKey;
use Comandi\Encryption\Key\PrivateLabelMasterKey;
use Comandi\Encryption\KeyManager\MasterKeyProvider\MasterKeyProvider;
use League\Flysystem\FilesystemInterface;
use Ramsey\Uuid\Uuid;

final class KeyManager
{
    /**
     * A UUID v5 namespace for private label master keys.
     *
     * @var string
     */
    private const PRIVATE_LABEL_KEY_NS = 'ee11c065-8851-43aa-8a6b-91b77deb4009';

    /**
     * The path in the Filesystem to store the manifest.
     *
     * @var string
     */
    private static $MANIFEST_PATH = '/private-label-keys.manifest';

    /**
     * The filesystem to store the manifest on.
     *
     * @var FilesystemInterface
     */
    private $filesystem;

    /**
     * Manifest that contains all private label keys.
     *
     * @var KeyManagerManifest
     */
    private $manifest;

    /**
     * Contains the provider for the Master Key.
     *
     * @var MasterKeyProvider
     */
    private $masterKeyProvider;

    /**
     * @param MasterKeyProvider $keyProvider
     * @param FilesystemInterface $filesystem Filesystem to store manifest
     */
    public function __construct(
        MasterKeyProvider $keyProvider,
        FilesystemInterface $filesystem)
    {
        $this->masterKeyProvider = $keyProvider;
        $this->filesystem = $filesystem;

        $this->manifest = $this->loadManifest();
    }

    /**
     * Return a new DataKey from a private label.
     *
     * @param $privateLabel
     * @param int $keyLength
     *
     * @return DataKey
     */
    public function generateDataKey($privateLabel, $keyLength): DataKey
    {
        $master_key = $this->getMasterKeyForPrivateLabel($privateLabel);

        // Generate a random data key
        $data_key_plaintext = \random_bytes($keyLength);

        // Encrypt the data key
        $data_key_ciphertext = EncryptionHelper::doEncrypt(
            $data_key_plaintext,
            $master_key->plaintext()
        );

        $data_key_id = Uuid::uuid5($master_key->keyId(), Uuid::uuid4())->toString();

        return DataKey::createNew(
            $privateLabel,
            $data_key_id,
            $master_key->keyId(),
            $data_key_ciphertext,
            $data_key_plaintext
        );
    }

    /**
     * Returns an unencrypted version of the Data Key.
     *
     * An unencrypted Data Key can be used to decrypt ciphertext.
     *
     * @param DataKey $key
     *
     * @return DataKey
     */
    public function decryptDataKey(DataKey $key): DataKey
    {
        $master_key = $this->manifest->fetchSpecificMasterKeyForPrivateLabel(
            $key->privateLabel(),
            $key->masterKeyId()
        );

        $decrypted_master_key = $this->decryptMasterKey(
            $master_key
        );

        $plaintext = EncryptionHelper::doDecrypt(
            $key->ciphertext(),
            $decrypted_master_key->plaintext()
        );

        // Return the data key with the plaintext.
        return $key->withPlaintext($plaintext);
    }

    /**
     * Returns the current Master Key for a private label.
     *
     * @param string $privateLabel
     *
     * @return PrivateLabelMasterKey
     */
    private function getMasterKeyForPrivateLabel(string $privateLabel): PrivateLabelMasterKey
    {
        try {
            $master_key = $this->manifest->fetchLatestMasterKeyForPrivateLabel($privateLabel);
        } catch (KeyDoesNotExist|PrivateLabelDoesNotExist $e) {
            $master_key = $this->createNewMasterKeyForPrivateLabel($privateLabel);
        }

        if ($master_key->isDecrypted()) {
            return $master_key;
        }

        return $this->decryptMasterKey($master_key);
    }

    /**
     * Decrypts a Master Key.
     *
     * The Master Key is used to encrypt or decrypt Data Keys.
     *
     * @param PrivateLabelMasterKey $key
     *
     * @return PrivateLabelMasterKey
     */
    private function decryptMasterKey(PrivateLabelMasterKey $key): PrivateLabelMasterKey
    {
        $decrypted_master_key = $this->masterKeyProvider->decryptMasterKey($key);

        $this->manifest->addPlaintextForKey($decrypted_master_key);

        return $decrypted_master_key;
    }

    /**
     * Generates a new Master Key for a private label.
     *
     * This automatically rotates the master key of the private label.
     *
     * @param string $privateLabel
     *
     * @return PrivateLabelMasterKey
     */
    private function createNewMasterKeyForPrivateLabel(string $privateLabel): PrivateLabelMasterKey
    {
        // Generate a new Key ID for our own key.
        $new_key_id = Uuid::uuid5(self::PRIVATE_LABEL_KEY_NS, $privateLabel)->toString();

        $master_key = $this->masterKeyProvider->generateMasterKeyForPrivateLabel(
            EncryptionHelper::keyLength(),
            $privateLabel,
            $new_key_id
        );

        $this->manifest->addKeyForPrivateLabel($master_key);
        $this->storeManifest();

        return $master_key;
    }

    /**
     * Loads the Key Manager Manifest from the filesystem.
     *
     * @return KeyManagerManifest
     */
    private function loadManifest(): KeyManagerManifest
    {
        if (!$this->filesystem->has(self::$MANIFEST_PATH)) {
            return KeyManagerManifest::createNew();
        }

        $contents = $this->filesystem->read(self::$MANIFEST_PATH);

        $manifest_array = \json_decode(\base64_decode($contents, true), true);

        return KeyManagerManifest::fromArray($manifest_array);
    }

    /**
     * Stores the Key Manager Manifest to the file system.
     */
    private function storeManifest()
    {
        if (!$this->manifest->hasChanged()) {
            return;
        }

        $array = $this->manifest->toArray();
        $content = \base64_encode(\json_encode($array));
        $this->filesystem->put(self::$MANIFEST_PATH, $content);

        $this->manifest->stored();
    }
}
