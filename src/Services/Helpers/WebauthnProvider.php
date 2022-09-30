<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use lbuchs\WebAuthn\WebAuthn;

/**
 * This service provides an lbuchs WebAuthn object configured with the global settings
 */
final class WebauthnProvider
{
    private ?WebAuthn $webauthn =  null;

    private string $rpId;
    private string $rpName;
    private ?array $allowedFormats;

    public function __construct(string $rpId, string $rpName, ?array $allowedFormats = null)
    {
        $this->rpId = $rpId;
        $this->rpName = $rpName;
        $this->allowedFormats = $allowedFormats;
    }

    private function createInstance(): WebAuthn
    {
        return new WebAuthn($this->rpName, $this->rpId, $this->allowedFormats);
    }

    public function getInstance(): WebAuthn
    {
        if ($this->webauthn === null) {
            $this->webauthn = $this->createInstance();
        }

        return $this->webauthn;
    }
}