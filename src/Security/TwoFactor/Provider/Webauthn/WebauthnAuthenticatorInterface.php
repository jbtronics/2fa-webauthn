<?php

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

interface WebauthnAuthenticatorInterface
{
    /**
     * Generates a webauthn signing request as an object which can directly be encoded to JSON and passed to navigator.credentials.get
     * @param  TwoFactorInterface  $user
     * @return \stdClass
     */
    public function getGenerateRequest(TwoFactorInterface $user): PublicKeyCredentialRequestOptions;

    /**
     * Checks if the given webauthn response is valid
     * @param  TwoFactorInterface  $user
     * @param  PublicKeyCredentialOptions  $request The request for which the response was generated, in the form it was returned by getGenerateRequest
     * @param  AuthenticatorAssertionResponse  $response The response from the browser, in the form it was returned by navigator.credentials.get
     * @return bool
     */
    public function checkRequest(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $response): bool;
}