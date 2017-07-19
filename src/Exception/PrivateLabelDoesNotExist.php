<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

class PrivateLabelDoesNotExist extends \RuntimeException implements ComandiEncryptionException
{
    public static function create($privateLabelName): self
    {
        return new self(sprintf(
            'Private label %s does not exist.',
            $privateLabelName
        ));
    }
}