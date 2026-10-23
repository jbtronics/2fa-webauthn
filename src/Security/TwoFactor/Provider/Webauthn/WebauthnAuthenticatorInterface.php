<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Webauthn\PublicKeyCredentialRequestOptions;

interface WebauthnAuthenticatorInterface
{
    /**
     * Generates a webauthn signing request as an object which can directly be encoded to JSON and passed to navigator.credentials.get.
     */
    public function generateAuthenticationRequest(TwoFactorInterface $user): PublicKeyCredentialRequestOptions;

    /**
     * Checks if the given webauthn response is valid.
     *
     * @param PublicKeyCredentialRequestOptions $request  The request for which the response was generated, in the form it was returned by generateAuthenticationRequest
     * @param string                            $response The JSON encoded response from the browser, in the form it was returned by navigator.credentials.get
     */
    public function checkAuthenticationResponse(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $response): bool;
}
