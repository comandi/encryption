<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

final class MasterKeyDoesNotExist extends \RuntimeException implements ComandiEncryptionException
{
    public static function create(string $keyId): self
    {
        $message = sprintf(
            'The Master Key with id "%s" is not available.',
            $keyId
        );

        return new static($message, 404);
    }
}