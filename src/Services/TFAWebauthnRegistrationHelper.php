<?php

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithms;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Symfony\Component\Security\Core\Security;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;

class TFAWebauthnRegistrationHelper
{
    private int $timeout;
    private WebauthnProvider $webauthnProvider;
    private Security $security;
    private PublicKeyCredentialSourceRepository $keyCredentialSourceRepository;
    private PSRRequestHelper $PSRRequestHelper;
    private WebAuthnRequestStorage $webAuthnRequestStorage;

    public function __construct(int $timeout, WebauthnProvider $webauthnProvider, Security $security,
        PublicKeyCredentialSourceRepository $keyCredentialSourceRepository, PSRRequestHelper $PSRRequestHelper,
        WebAuthnRequestStorage $webAuthnRequestStorage)
    {
        $this->timeout = $timeout;
        $this->webauthnProvider = $webauthnProvider;
        $this->security = $security;
        $this->keyCredentialSourceRepository = $keyCredentialSourceRepository;
        $this->PSRRequestHelper = $PSRRequestHelper;
        $this->webAuthnRequestStorage = $webAuthnRequestStorage;
    }

    /**
     * Generate a new registration request for the given user and save it in the session as active registration.
     * @param  TwoFactorInterface|null  $user The user for which the registration request should be generated. If null the current user is used.
     * @return PublicKeyCredentialCreationOptions
     */
    public function generateRegistrationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialCreationOptions
    {
        //If no user is given use the current user
        if ($user === null) {
            $current_user = $this->security->getUser();
            if (!$current_user instanceof TwoFactorInterface) {
                throw new \InvalidArgumentException('The current user does not implement TwoFactorInterface. You have to explicitly pass a user to this method.');
            }
            $user = $current_user;
        }

        $challenge = random_bytes(32);


        //The algorithms we allow
        $publicKeyCredentialParametersList = [
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES512),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS512),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ED256),
            new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_EdDSA),
        ];

        //Exclude all existing credentials
        $excludedCredentials = array_map(
            static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                return $credential->getPublicKeyCredentialDescriptor();
            },
            $this->keyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        $data = new PublicKeyCredentialCreationOptions(
            $this->webauthnProvider->getPublicKeyCredentialRpEntity(),
            $user->getWebAuthnUser(),
            $challenge,
            $publicKeyCredentialParametersList,
            $this->timeout,
            $excludedCredentials
        );

        //Save creation options in the session, so it can be used for validation later
        $this->webAuthnRequestStorage->setActiveRegistrationRequest($data);

        return $data;
    }

    /**
     * Generate a new registration request for the given user and returns it as JSON, so that it can be passed to the browser.
     * @param  TwoFactorInterface|null  $user
     * @return string The registration request as JSON
     */
    public function generateRegistrationRequestAsJSON(?TwoFactorInterface $user = null): string
    {
        return json_encode($this->generateRegistrationRequest($user), JSON_THROW_ON_ERROR);
    }

    /**
     * Validate the given registration response and returns the new key.
     * If the response is invalid an exception is thrown.
     * @param  string  $jsonResponse The json encoded response from the browser
     * @return PublicKeyCredentialSource The credential returned from the browser
     */
    public function checkRegistrationResponse(string $jsonResponse): PublicKeyCredentialSource
    {
        $publicKeyCredential = $this->webauthnProvider->getPublicKeyCredentialLoader()->load($jsonResponse);
        $authenticatorAttestationResponse = $publicKeyCredential->getResponse();

        if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
            throw new \RuntimeException('The given response is not an AuthenticatorAttestationResponse!');
        }

        $serverRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();
        if ($serverRequest === null) {
            throw new \RuntimeException('Could not get the current request!');
        }

        $activeRegistration = $this->webAuthnRequestStorage->getActiveRegistrationRequest();
        if ($activeRegistration === null) {
            throw new \RuntimeException('No active registration request found!');
        }

        return $this->webauthnProvider->getAuthenticatorAttestationResponseValidator()->check(
            $authenticatorAttestationResponse,
            $activeRegistration,
            $serverRequest
        );
    }


}