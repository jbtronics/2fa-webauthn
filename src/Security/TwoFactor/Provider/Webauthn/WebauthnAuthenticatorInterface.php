<?php

namespace jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use jbtronics\TFAWebauthn\Model\TwoFactorInterface;

interface WebauthnAuthenticatorInterface
{
    /**
     * Generates a webauthn signing request as an object which can directly be encoded to JSON and passed to navigator.credentials.get
     * @param  TwoFactorInterface  $user
     * @return \stdClass
     */
    public function getGenerateRequest(TwoFactorInterface $user): \stdClass;

    /**
     * Checks if the given webauthn response is valid
     * @param  TwoFactorInterface  $user
     * @param  \stdClass  $request The request for which the response was generated, in the form it was returned by getGenerateRequest
     * @param  \stdClass  $response The response from the browser, in the form it was returned by navigator.credentials.get
     * @return bool
     */
    public function checkRequest(TwoFactorInterface $user, \stdClass $request, \stdClass $response): bool;
}