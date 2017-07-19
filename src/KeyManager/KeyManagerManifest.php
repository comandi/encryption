<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager;

use Comandi\Encryption\Exception\KeyAlreadyExists;
use Comandi\Encryption\Exception\KeyDoesNotExist;
use Comandi\Encryption\Exception\PrivateLabelDoesNotExist;
use Comandi\Encryption\Key\PrivateLabelMasterKey;
use DusanKasan\Knapsack\Collection;

final class KeyManagerManifest
{
    /**
     * Whether this Manifest has changed.
     *
     * @var bool
     */
    private $changed = false;

    /**
     * List of Master Keys for a specific Private Label
     *
     * This structure does *not* contains the actual keys, those are
     * in the {@see ::$availableKeys} property.
     *
     * @var array
     */
    private $privateLabels = [];

    /**
     * List of all available Master Keys
     *
     * @var PrivateLabelMasterKey[]
     */
    private $availableKeys = [];

    /**
     * List of Master Keys that are decrypted.
     *
     * @var PrivateLabelMasterKey[]
     */
    private $plaintextKeys = [];

    private function __construct(array $privateLabels, array $availableKeys)
    {
        $this->privateLabels = $privateLabels;
        $this->availableKeys = $availableKeys;
    }

    /**
     * When destructing this object, make sure that all plaintext keys
     * are sealed and removed.
     */
    public function __destruct()
    {
        $this->seal();
    }

    /**
     * Returns the current key for a private label.
     *
     * @param string $privateLabel
     *
     * @return PrivateLabelMasterKey
     */
    public function fetchLatestMasterKeyForPrivateLabel(string $privateLabel): PrivateLabelMasterKey
    {
        if (!array_key_exists($privateLabel, $this->privateLabels)) {
            throw PrivateLabelDoesNotExist::create($privateLabel);
        }

        $current_key = $this->privateLabels[$privateLabel]['currentKey'];

        return $this->fetchSpecificMasterKeyForPrivateLabel($privateLabel, $current_key);
    }

    /**
     * Retrieve a specific key for a specific private label.
     *
     * @param string $privateLabel
     * @param string $keyId
     *
     * @return PrivateLabelMasterKey
     */
    public function fetchSpecificMasterKeyForPrivateLabel(string $privateLabel, string $keyId): PrivateLabelMasterKey
    {
        if (!array_key_exists($privateLabel, $this->privateLabels)) {
            throw PrivateLabelDoesNotExist::create($privateLabel);
        }

        // Check whether the specified key is available.
        if (!array_key_exists($keyId, $this->availableKeys)) {
            throw KeyDoesNotExist::create($privateLabel);
        }

        // Check whether the keys is already decrypted.
        // If so, return it, because it saves a decryption operation
        if (array_key_exists($keyId, $this->plaintextKeys)) {
            return $this->fetchKeyWithPlaintext($keyId);
        }

        // Otherwise, return the encrypted Master Key.
        return $this->availableKeys[$keyId];
    }

    /**
     * Add the plain text for a private label key.
     *
     * @param PrivateLabelMasterKey $masterKey
     */
    public function addPlaintextForKey(PrivateLabelMasterKey $masterKey)
    {
        if (!$masterKey->isDecrypted()) {
            throw new \LogicException('Master key '.$masterKey->keyId().' is not decrypted.');
        }

        $this->plaintextKeys[$masterKey->keyId()] = $masterKey;
    }

    /**
     * Whether this Manifest has changed.
     *
     * @return bool
     */
    public function hasChanged(): bool
    {
        return $this->changed;
    }

    public function stored()
    {
        $this->changed = false;
    }

    /**
     * Add a new key for a private label.
     *
     * This key will become the new default key.
     *
     * @param PrivateLabelMasterKey $masterKey
     */
    public function addKeyForPrivateLabel(PrivateLabelMasterKey $masterKey)
    {
        if (array_key_exists($masterKey->keyId(), $this->availableKeys)) {
            throw KeyAlreadyExists::create($masterKey->keyId());
        }

        $this->changed = true;

        $label = $masterKey->privateLabel();
        if (!array_key_exists($label, $this->privateLabels)) {
            $this->privateLabels[$label] = [
                'currentKey' => null,
                'availableKeys' => [],
            ];
        }

        $this->rotateKey($masterKey);
    }

    /**
     * Rotate a key for a private label.
     *
     * @param PrivateLabelMasterKey $masterKey
     */
    private function rotateKey(PrivateLabelMasterKey $masterKey)
    {
        $this->changed = true;

        $this->availableKeys[$masterKey->keyId()] = $masterKey;

        $label = $this->privateLabels[$masterKey->privateLabel()];

        $current_key_id = $label['currentKey'];
        $available_keys = $label['availableKeys'];

        if (null !== $current_key_id) {
            $available_keys[$current_key_id] = $current_key_id;
        }

        $available_keys[$masterKey->keyId()] = $masterKey->keyId();

        $new_label = [
            'currentKey' => $masterKey->keyId(),
            'availableKeys' => $available_keys,
        ];

        $this->privateLabels[$masterKey->privateLabel()] = $new_label;

        if ($masterKey->isDecrypted()) {
            $this->addPlaintextForKey($masterKey);
        }
    }

    /**
     * Return the Key Manager Manifest as an array.
     *
     * @return array
     */
    public function toArray(): array
    {
        $available_keys = Collection::from($this->availableKeys)
            ->map(function (PrivateLabelMasterKey $key) {
                return $key->toArray();
            })->toArray();

        return [
            'privateLabels' => $this->privateLabels,
            'availableKeys' => $available_keys,
        ];
    }

    /**
     * Create a Key Manager Manifest from an array.
     *
     * @param array $state
     *
     * @return KeyManagerManifest
     */
    public static function fromArray(array $state): self
    {
        if (!array_key_exists('privateLabels', $state)) {
            throw new \LogicException("Key 'privateLabels' does not exist on serialized Key Manager Manifest");
        }

        if (!array_key_exists('availableKeys', $state)) {
            throw new \LogicException("Key 'availableKeys' does not exist on serialized Key Manager Manifest");
        }

        $available_keys = Collection::from($state['availableKeys'])
            ->map(function ($key_array) {
                return PrivateLabelMasterKey::fromArray($key_array);
            })
            ->toArray();

        return new self(
            $state['privateLabels'],
            $available_keys
        );
    }

    /**
     * Create a new Key Manager Manifest.
     *
     * @return KeyManagerManifest
     */
    public static function createNew(): self
    {
        $instance = new self([], []);
        $instance->changed = true;

        return $instance;
    }

    /**
     * Seal and removes all plaintext keys.
     */
    public function seal(): void
    {
        foreach ($this->plaintextKeys as $index => $plaintextKey) {
            $plaintextKey->seal();
            unset($this->plaintextKeys[$index]);
        }
    }

    /**
     * Return a clone of this key.
     *
     * Cloning the key is necessary to prevent side effects when the
     * {@see ::seal()} method is called.
     *
     * Otherwise, sealing the keys would have side effects for code that
     * might still be using that key.
     */
    private function fetchKeyWithPlaintext(string $keyId): PrivateLabelMasterKey
    {
        $cloned_key = clone $this->plaintextKeys[$keyId];
        return $cloned_key;
    }
}
