<?php

declare(strict_types=1);

namespace Comandi\Encryption\Exception;

final class KeyDoesNotExist extends \RuntimeException
{
    public static function create(string $privateLabel): self
    {
        return new self(sprintf("No key exists for private label '%s'.", $privateLabel));
    }
}
