<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

final class KeyAlreadyExists extends \RuntimeException implements ComandiEncryptionException
{
    public static function create($keyName): self
    {
        return new self(sprintf("The key with id '%s' already exists.", $keyName));
    }
}
