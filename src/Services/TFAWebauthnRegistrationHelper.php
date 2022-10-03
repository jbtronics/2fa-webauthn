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

    public function getRegistrationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialCreationOptions
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

    public function getRegistrationRequestAsJSON(?TwoFactorInterface $user = null): string
    {
        return json_encode($this->getRegistrationRequest(), JSON_THROW_ON_ERROR);
    }

    public function checkRegistration(string $jsonResponse): PublicKeyCredentialSource
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