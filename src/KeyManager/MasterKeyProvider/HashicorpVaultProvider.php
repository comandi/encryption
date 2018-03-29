<?php

declare(strict_types=1);

namespace Comandi\Encryption\KeyManager\MasterKeyProvider;

use Comandi\Encryption\Exception\CommunicationException;
use Comandi\Encryption\Key\PrivateLabelMasterKey;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;

/**
 * Hashicorp Vault Master Key Provider
 *
 * This Provider uses the transit secret backend of Hashicorp Vault
 * to generate data keys and decrypt Master Keys.
 */
final class HashicorpVaultProvider implements MasterKeyProvider
{
    /**
     * @var string
     */
    private $token;

    /**
     * @var string
     */
    private $keyName;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var string
     */
    private $url;

    private $defaultHeaders = [
        'Accept' => 'application/json',
        'Content-Type' => 'application/json',
    ];

    public function __construct(Client $httpClient, HashicorpVaultOptions $options)
    {
        $this->url = $options->backendUrl();
        $this->token = $options->token();
        $this->keyName = $options->keyName();

        $this->client = $httpClient;
        $this->defaultHeaders['X-Vault-Token'] = $this->token;
    }

    /**
     * Returns the name of the key provider.
     *
     * @return string
     */
    public static function providerName(): string
    {
        return 'Hashicorp-Vault';
    }

    public function generateMasterKeyForPrivateLabel(
        int $keyLengthInBytes,
        string $privateLabel,
        string $keyId
    ): PrivateLabelMasterKey
    {
        $key_response = $this->requestDataKey($keyLengthInBytes);

        return PrivateLabelMasterKey::createNew(
            $privateLabel,
            $keyId,
            'vault:' . $this->keyName,
            $key_response['ciphertext'],
            \base64_decode($key_response['plaintext'])
        );
    }

    public function decryptMasterKey(PrivateLabelMasterKey $key): PrivateLabelMasterKey
    {
        if ($key->isDecrypted()) {
            return $key;
        }

        $vault_master_key = substr($key->masterKeyId(), 6);

        $plaintext = $this->decryptDataKey($key->ciphertext(), $vault_master_key);

        return $key->withPlaintext($plaintext);
    }

    public function acceptsMasterKey(PrivateLabelMasterKey $key): bool
    {
        return 'vault' === substr($key->masterKeyId(), 0, 5);
    }

    /**
     * Request a data key of the given length in bytes.
     *
     * It will return an array with two keys: ciphertext and plaintext.
     * - ciphertext: contains the data key in ciphertext
     * - plaintext: contains the data key in plaintext
     *
     * The ciphertext can be stored safely, and can later be decrypted
     * again by Vault.
     *
     * The plaintext should *never* leave the system and should only be used
     * as shortly as possible for the operations that need to be done with it.
     *
     * @param int $keyLengthInBytes
     *
     * @return array
     */
    private function requestDataKey(int $keyLengthInBytes): array
    {
        switch ($keyLengthInBytes) {
            case 16:
            case 32:
            case 64:
                break;

            default:
                throw new \InvalidArgumentException('Requested key length can only be 16, 32 or 64 bytes.');
        }

        $key_length_in_bits = $keyLengthInBytes * 8;

        $request = new Request(
            'POST',
            $this->url . '/datakey/plaintext/' . $this->keyName,
            $this->defaultHeaders,
            \GuzzleHttp\json_encode(['bits' => $key_length_in_bits])
        );

        return $this->doRequest($request);
    }

    /**
     * Decrypt a data key and return the plaintext
     */
    private function decryptDataKey(string $ciphertext, string $keyName): string
    {
        $request = new Request(
            'POST',
            $this->url . '/decrypt/' . $keyName,
            $this->defaultHeaders,
            \GuzzleHttp\json_encode(['ciphertext' => $ciphertext])
        );

        $response = $this->doRequest($request);

        return \base64_decode($response['plaintext']);
    }

    private function doRequest(Request $request): array
    {
        try {
            $response = $this->client->send($request);
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() === 403) {
                throw CommunicationException::create('Invalid Vault token given');
            }

            throw $e;
        }

        $body = $response->getBody()->getContents();

        return \GuzzleHttp\json_decode($body, true)['data'];
    }
}