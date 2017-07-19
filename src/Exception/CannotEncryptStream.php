<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

use RuntimeException;

final class CannotEncryptStream extends RuntimeException implements ComandiEncryptionException
{
    public static function create()
    {
        return new self('Streaming encryption / decryption is not yet supported.');
    }
}
