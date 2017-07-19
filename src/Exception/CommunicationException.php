<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

class CommunicationException extends \RuntimeException implements ComandiEncryptionException
{
    public static function create($message): self
    {
        return new self($message);
    }
}