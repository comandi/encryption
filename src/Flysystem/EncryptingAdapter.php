<?php

declare(strict_types=1);

namespace Comandi\Encryption\Flysystem;

use Comandi\Encryption\EncryptionHelper;
use Comandi\Encryption\Exception\CannotEncryptStream;
use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;

final class EncryptingAdapter implements AdapterInterface
{
    /**
     * @var AdapterInterface
     */
    private $backend;

    /**
     * @var EncryptionHelper
     */
    private $encryptionHelper;

    /**
     * @var string
     */
    private $privateLabel;

    /**
     * EncryptingAdapter constructor.
     *
     * @param AdapterInterface $backend
     * @param EncryptionHelper $encryptionHelper
     * @param string           $privateLabel
     */
    public function __construct(AdapterInterface $backend, EncryptionHelper $encryptionHelper, string $privateLabel)
    {
        $this->backend = $backend;
        $this->encryptionHelper = $encryptionHelper;
        $this->privateLabel = $privateLabel;
    }

    /**
     * Read a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function read($path)
    {
        $ciphertext = $this->backend->read($path)['contents'];

        $plaintext = $this->encryptionHelper->decrypt($ciphertext);

        return [
            'contents' => $plaintext,
            'path' => $path,
        ];
    }

    /**
     * Write a new file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function write($path, $contents, Config $config)
    {
        $ciphertext = $this->encryptionHelper->encrypt($this->privateLabel, $contents);

        return $this->backend->write($path, $ciphertext, $config);
    }

    /**
     * Update a file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function update($path, $contents, Config $config)
    {
        $ciphertext = $this->encryptionHelper->encrypt($this->privateLabel, $contents);

        return $this->backend->update($path, $ciphertext, $config);
    }

    /**
     * Rename a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     */
    public function rename($path, $newpath)
    {
        return $this->backend->rename($path, $newpath);
    }

    /**
     * Copy a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     */
    public function copy($path, $newpath)
    {
        return $this->backend->copy($path, $newpath);
    }

    /**
     * Delete a file.
     *
     * @param string $path
     *
     * @return bool
     */
    public function delete($path)
    {
        return $this->backend->delete($path);
    }

    /**
     * Delete a directory.
     *
     * @param string $dirname
     *
     * @return bool
     */
    public function deleteDir($dirname)
    {
        return $this->backend->deleteDir($dirname);
    }

    /**
     * Create a directory.
     *
     * @param string $dirname directory name
     * @param Config $config
     *
     * @return array|false
     */
    public function createDir($dirname, Config $config)
    {
        return $this->backend->createDir($dirname, $config);
    }

    /**
     * Set the visibility for a file.
     *
     * @param string $path
     * @param string $visibility
     *
     * @return array|false file meta data
     */
    public function setVisibility($path, $visibility)
    {
        return $this->backend->setVisibility($path, $visibility);
    }

    /**
     * Check whether a file exists.
     *
     * @param string $path
     *
     * @return array|bool|null
     */
    public function has($path)
    {
        return $this->backend->has($path);
    }

    /**
     * Write a new file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function writeStream($path, $resource, Config $config)
    {
        throw CannotEncryptStream::create();
    }

    /**
     * Update a file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function updateStream($path, $resource, Config $config)
    {
        throw CannotEncryptStream::create();
    }

    /**
     * Read a file as a stream.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function readStream($path)
    {
        throw CannotEncryptStream::create();
    }

    /**
     * List contents of a directory.
     *
     * @param string $directory
     * @param bool   $recursive
     *
     * @return array
     */
    public function listContents($directory = '', $recursive = false)
    {
        return $this->backend->listContents($directory, $recursive);
    }

    /**
     * Get all the meta data of a file or directory.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMetadata($path)
    {
        return $this->backend->getMetadata($path);
    }

    /**
     * Get all the meta data of a file or directory.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getSize($path)
    {
        // There is no way to return the size of the original data.
        return false;
    }

    /**
     * Get the mimetype of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMimetype($path)
    {
        // There is no way to return the mime type of the original data.
        return false;
    }

    /**
     * Get the timestamp of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getTimestamp($path)
    {
        return $this->backend->getTimestamp($path);
    }

    /**
     * Get the visibility of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getVisibility($path)
    {
        return $this->backend->getVisibility($path);
    }
}
