<?php

use Behat\Behat\Context\Context;
use Comandi\Encryption\Key\DataKey;
use Comandi\Encryption\Key\PrivateLabelMasterKey;
use Comandi\Encryption\KeyManager\KeyManager;
use Comandi\Encryption\KeyManager\MasterKeyProvider\AwsKmsMasterKeyProvider;
use Comandi\Encryption\KeyManager\MasterKeyProvider\AwsKmsOptions;
use Comandi\Encryption\KeyManager\MasterKeyProvider\HashicorpVaultProvider;
use Comandi\Encryption\KeyManager\MasterKeyProvider\InMemoryMasterKeyProvider;
use Comandi\Encryption\KeyManager\MasterKeyProvider\MasterKeyProvider;
use Comandi\Encryption\KeyManager\MasterKeyProvider\HashicorpVaultOptions;
use Webmozart\Assert\Assert;

class FeatureContext implements Context
{
    /**
     * Prophecy instance used to create mocks and stubs.
     *
     * @var \Prophecy\Prophet
     */
    private $prophet;

    /**
     * @var string
     */
    private $keyProviderType = '';

    /**
     * @var MasterKeyProvider
     */
    private $masterKeyProvider;

    /**
     * @var PrivateLabelMasterKey
     */
    private $masterKey;

    private $privateKeyString = 'ddeb1e8ae48bd6b08fa3703ba095586c11a360ef7a60dcf83172055c31f45433';

    /**
     * @var string
     */
    private $serializedMasterKey;

    /**
     * @var PrivateLabelMasterKey
     */
    private $deserializedMasterKey;

    /**
     * @var KeyManager
     */
    private $keyManager;

    /**
     * @var DataKey
     */
    private $dataKey;

    /**
     * Contains the plaintext of the data key.
     *
     * This should never be done in production but it is
     * required to check decryption of the Data Key.
     *
     * @var string
     */
    private $dataKeyPlaintext;

    public function __construct()
    {
        $this->prophet = new \Prophecy\Prophet();
    }

    /**
     * @Given an :keyProviderType Master Key Provider
     */
    public function anMasterKeyProvider($keyProviderType)
    {
        $this->keyProviderType = $keyProviderType;

    }

    /**
     * @When I instantiate the provider
     */
    public function iInstantiateTheProvider()
    {
        switch ($this->keyProviderType) {
            case AwsKmsMasterKeyProvider::providerName():
                $client = $this->prophet->prophesize(\Aws\Kms\KmsClient::class);

                $client->generateDataKey([
                    'KeyId' => '1234',
                    'NumberOfBytes' => 32
                ])->willReturn([
                    'KeyId' => '1234',
                    'CiphertextBlob' => 'some-cipher-text',
                    'Plaintext' => $this->privateKeyString,
                ]);

                $client->decrypt([
                    'CiphertextBlob' => 'some-cipher-text',
                ])->willReturn([
                    'KeyId' => '1234',
                    'Plaintext' => $this->privateKeyString,
                ]);

                $this->masterKeyProvider = new AwsKmsMasterKeyProvider(
                    $client->reveal(),
                    new AwsKmsOptions('1234')
                );
                break;
            case InMemoryMasterKeyProvider::providerName():
                $this->masterKeyProvider = new InMemoryMasterKeyProvider(
                    \hex2bin($this->privateKeyString)
                );
                break;

            case HashicorpVaultProvider::providerName():
                $generate_response = new \GuzzleHttp\Psr7\Response(
                    200,
                    [],
                    json_encode(['data' => [
                        'ciphertext' => $this->privateKeyString,
                        'plaintext' => $this->privateKeyString,
                    ]])
                );

                $decrypt_response = new \GuzzleHttp\Psr7\Response(
                    200,
                    [],
                    json_encode(['data' => [
                        'plaintext' => $this->privateKeyString,
                    ]])
                );

                $mock = new \GuzzleHttp\Handler\MockHandler([
                    $generate_response,
                    $decrypt_response,
                ]);

                $requests = [];

                $handler = \GuzzleHttp\HandlerStack::create($mock);
                $handler->push(\GuzzleHttp\Middleware::history($requests));

                $this->masterKeyProvider = new HashicorpVaultProvider(
                    new \GuzzleHttp\Client(['handler' => $handler]),
                    new HashicorpVaultOptions(
                        'http://some-url', // Not really used in the tests.
                        'some-kind-of-uuid-token', // Not really used in the tests.
                        'test' // Not really used in the tests.
                    )
                );
                break;

            default:
                throw new \InvalidArgumentException('Master Key Provider ' . $this->keyProviderType . ' does not exist.');
        }


    }

    /**
     * @Then I have a Master Key Provider
     */
    public function iHaveAMasterKeyProvider()
    {
        Assert::isInstanceOf($this->masterKeyProvider, MasterKeyProvider::class);
    }

    /**
     * @When I generate a Master Key for private label :label
     */
    public function iGenerateAMasterKey($label)
    {
        $this->masterKey = $this->masterKeyProvider->generateMasterKeyForPrivateLabel(
            32,
            $label,
            'dummy-key'
        );
    }

    /**
     * @Then I have a Master Key
     */
    public function iHaveAMasterKey()
    {
        Assert::isInstanceOf($this->masterKey, PrivateLabelMasterKey::class);
    }

    /**
     * @Then the Master Key has Master Key ID :keyId
     */
    public function theDataKeyHasMasterKeyId($keyId)
    {
        Assert::eq($this->masterKey->masterKeyId(), $keyId);
    }

    /**
     * @Given /^I serialize the Master Key$/
     */
    public function iSerializeTheMasterKey()
    {
        $this->serializedMasterKey = $this->masterKey->toString();
    }

    /**
     * @Given /^I deserialize and decrypt the serialized Master Key$/
     */
    public function iDeserializeAndDecryptTheSerializedMasterKey()
    {
        $master_key = PrivateLabelMasterKey::fromString($this->serializedMasterKey);

        $this->deserializedMasterKey = $this->masterKeyProvider->decryptMasterKey($master_key);
    }

    /**
     * @Then /^the Master Key and the Deserialized Master Key are the same$/
     */
    public function theMasterKeyAndTheDeserializedMasterKeyAreTheSame()
    {
        Assert::same($this->deserializedMasterKey->toString(), $this->masterKey->toString());
    }

    /**
     * @Then I have a Key Manager
     */
    public function iHaveAKeyManager()
    {
        Assert::isInstanceOf($this->keyManager, KeyManager::class);
    }

    /**
     * @Given a Key Manager
     */
    public function aKeyManager()
    {
        $this->keyManager = new KeyManager(
            new InMemoryMasterKeyProvider(\hex2bin($this->privateKeyString)),
            new \League\Flysystem\Filesystem(new \League\Flysystem\Memory\MemoryAdapter())
        );
    }

    /**
     * @When the Key Manager creates a Data Key
     */
    public function theKeyManagerCreatesADataKey()
    {
        $this->dataKey = $this->keyManager->generateDataKey('test', \Comandi\Encryption\EncryptionHelper::keyLength());
    }

    /**
     * @Then I have a Data Key
     */
    public function iHaveADataKey()
    {
        Assert::isInstanceOf($this->dataKey, DataKey::class);
    }

    /**
     * @When the Key Manager decrypts the Data Key
     */
    public function theKeyManagerDecryptsTheDataKey()
    {
        $this->dataKey = $this->keyManager->decryptDataKey($this->dataKey);
    }

    /**
     * @Then the plaintext Data Keys are the same
     */
    public function thePlaintextDataKeysAreTheSame()
    {
        Assert::same($this->dataKeyPlaintext, $this->dataKey->plaintext());
    }

    /**
     * @When the Data Key is sealed
     */
    public function theDataKeyIsSealed()
    {
        $this->dataKeyPlaintext = $this->dataKey->plaintext();
        $this->dataKey->seal();
    }
}
