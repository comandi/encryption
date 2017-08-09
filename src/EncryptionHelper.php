<?php

declare(strict_types=1);

namespace Comandi\Encryption;

use Comandi\Encryption\Key\DataKey;
use Comandi\Encryption\KeyManager\KeyManager;
use function mb_substr;
use function sodium_crypto_aead_chacha20poly1305_ietf_decrypt;
use function sodium_crypto_aead_chacha20poly1305_ietf_encrypt;
use function sodium_memzero;
use const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
use const SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;

final class EncryptionHelper
{
    const DATA_KEY = 'key';
    const CIPHERTEXT = 'ct';

    /**
     * @var KeyManager
     */
    private $keyManager;

    /**
     * @param KeyManager $keyManager
     */
    public function __construct(KeyManager $keyManager)
    {
        $this->keyManager = $keyManager;
    }

    /**
     * Encrypts a string.
     *
     * @param string $privateLabel
     * @param string $plaintext
     *
     * @return string
     */
    public function encrypt(string $privateLabel, string $plaintext): string
    {
        // Generate the data key
        $data_key = $this->keyManager->generateDataKey($privateLabel, self::keyLength());

        // Encrypt the plaintext
        $ciphertext = self::doEncrypt(
            $plaintext,
            $data_key->plaintext()
        );

        sodium_memzero($plaintext);

        // Wrap the encrypted data key and the ciphertext to keep them together
        $wrapped_contents = \json_encode([
            self::DATA_KEY => $data_key->toString(),
            self::CIPHERTEXT => \bin2hex($ciphertext),
        ]);

        // Encode the wrapped contents for storage
        $wrapped_text = \base64_encode($wrapped_contents);

        return $wrapped_text;
    }

    /**
     * Decrypts a string.
     *
     * @param string $ciphertext
     *
     * @return string
     */
    public function decrypt(string $ciphertext): string
    {
        // Unwrap the contents
        $wrapped_contents = \json_decode(\base64_decode($ciphertext, true), true);

        // Retrieve the encrypted data key
        $encrypted_data_key = DataKey::fromString($wrapped_contents[self::DATA_KEY]);

        // Decrypt and retrieve the data key
        $decrypted_key = $this->keyManager->decryptDataKey($encrypted_data_key);

        // Decrypt the ciphertext
        $plaintext = self::doDecrypt(
            \hex2bin($wrapped_contents[self::CIPHERTEXT]),
            $decrypted_key->plaintext()
        );

        return $plaintext;
    }

    /**
     * Performs the actual encryption
     *
     * Not for external use.
     *
     * @internal
     */
    public static function doEncrypt(string $plaintext, string $key): string
    {
        $nonce = \random_bytes(self::nonceLength());

        $ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            $nonce,
            $nonce,
            $key
        );

        sodium_memzero($key);
        sodium_memzero($plaintext);

        return $nonce . $ciphertext;
    }

    /**
     * Performs the actual decryption.
     *
     * Not for external use.
     *
     * @internal
     */
    public static function doDecrypt(string $message, string $key): string
    {
        // Retrieve the nonce and the ciphertext.
        $nonce = mb_substr($message, 0, self::nonceLength(), '8bit');
        $ciphertext = mb_substr($message, self::nonceLength(), null, '8bit');

        // Decrypt the ciphertext
        $plaintext = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            $nonce,
            $nonce,
            $key
        );

        if (!is_string($plaintext)) {
            throw new \RuntimeException('Cannot decrypt message.');
        }

        sodium_memzero($key);

        return $plaintext;
    }

    /**
     * Return the required key length for data keys.
     */
    public static function keyLength(): int
    {
        return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
    }

    /**
     * Return the nonce length required for decryption.
     */
    private static function nonceLength(): int
    {
        return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;
    }
}
