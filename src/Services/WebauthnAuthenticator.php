<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;

class WebauthnAuthenticator implements WebauthnAuthenticatorInterface
{

    private U2FAppIDProvider $u2fAppIDProvider;
    private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository;

    protected string $requireUserVerification = "discouraged";
    protected int $timeout;
    protected ?string $rpID;
    protected WebauthnProvider $webauthnProvider;
    protected PSRRequestHelper $PSRRequestHelper;


    public function __construct(U2FAppIDProvider $u2FAppIDProvider, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        WebauthnProvider $webauthnProvider, PSRRequestHelper $PSRRequestHelper, int $timeout, ?string $rpID)
    {
        $this->u2fAppIDProvider = $u2FAppIDProvider;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->webauthnProvider = $webauthnProvider;
        $this->PSRRequestHelper = $PSRRequestHelper;
        $this->timeout = $timeout;
        $this->rpID = $rpID;
    }

    public function generateAuthenticationRequest(?TwoFactorInterface $user = null): PublicKeyCredentialRequestOptions
    {
        if ($user === null) {
            throw new \LogicException('You have to pass a user to this method!');
        }

        //Retrieve the registered keys for the user
        $allowedCredentials = array_map(
            static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                return $credential->getPublicKeyCredentialDescriptor();
            },
            $this->publicKeyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        //Generate a random challenge
        $challenge = random_bytes(32);

        //Add the U2F appID extension for backward compatibility
        $extensions =  AuthenticationExtensionsClientInputs::create([
            new AuthenticationExtension('appid', $this->u2fAppIDProvider->getAppID())]);

        //Set options
        $request = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->rpID,
            $allowedCredentials,
            $this->requireUserVerification,
            $this->timeout,
            $extensions,
        );

        //Add the U2F appID extension for backward compatibility
        $request->extensions->extensions['appid'] = $this->u2fAppIDProvider->getAppID();
        //$request->addExtension());

        return $request;
    }

    public function checkAuthenticationResponse(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $jsonResponse): bool
    {
        $publicKeyCredentialLoader = $this->webauthnProvider->getPublicKeyCredentialLoader();
        $validator = $this->webauthnProvider->getAuthenticatorAssertionResponseValidator();

        //Check that the JSON encoded response is valid
        $publicKeyCredential = $publicKeyCredentialLoader->load($jsonResponse);
        $authenticatorAssertionResponse = $publicKeyCredential->response;
        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            return false;
        }

        //We need a PSR conform version of our current request, so the webauthn library can get the currently used hostname (needed in case no rpId was explicitly set)
        $psrRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();

        if ($psrRequest === null) {
            throw new \RuntimeException('Could not get current request as PSR7 request!');
        }

        //Do the check
        try {
            $publicKeyCredentialSource = $validator->check(
                $publicKeyCredential->rawId,
                $authenticatorAssertionResponse,
                $request,
                $psrRequest,
                $user->getWebAuthnUser()->id
            );

            return true;
        } catch (\Throwable $e) {
            //If any exception happens during the check, the check failed, and we do not log the user in
            return false;
        }
    }
}