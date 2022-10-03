<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\KeyCollector;
use jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RequestStack;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorSelectionCriteria;
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

    public function getGenerateRequest(?TwoFactorInterface $user = null): PublicKeyCredentialRequestOptions
    {
        //Retrieve the registered keys for the user
        $allowedCredentials = array_map(
            static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                return $credential->getPublicKeyCredentialDescriptor();
            },
            $this->publicKeyCredentialSourceRepository->findAllForUserEntity($user->getWebAuthnUser())
        );

        //Generate a random challenge
        $challenge = random_bytes(32);

        $request = new PublicKeyCredentialRequestOptions($challenge);
        //Set options
        $request->setRpId($this->rpID);
        $request->setTimeout($this->timeout);
        $request->setUserVerification($this->requireUserVerification);

        $request->allowCredentials($allowedCredentials);

        //Add the U2F appID extension for backward compatibility
        $request->addExtension(new AuthenticationExtension('appid', $this->u2fAppIDProvider->getAppID()));

        return $request;
    }

    public function checkRequest(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $jsonResponse): bool
    {
        $publicKeyCredentialLoader = $this->webauthnProvider->getPublicKeyCredentialLoader();
        $validator = $this->webauthnProvider->getAuthenticatorAssertionResponseValidator();

        //Check that the JSON encoded response is valid
        $publicKeyCredential = $publicKeyCredentialLoader->load($jsonResponse);
        $authenticatorAssertionResponse = $publicKeyCredential->getResponse();
        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            return false;
        }

        //We need a PSR conform version of our current request, so the webauthn library can get the currently used hostname (needed in case no rpId was explicitly set)
        $psrRequest = $this->PSRRequestHelper->getCurrentRequestAsPSR7();

        //Do the check
        try {
            $publicKeyCredentialSource = $validator->check(
                $publicKeyCredential->getRawId(),
                $authenticatorAssertionResponse,
                $request,
                $psrRequest,
                $user->getWebAuthnUser()->getName()
            );

            return true;
        } catch (\Throwable $e) {
            //If any exception happens during the check, the check failed and we do not log the user in
            return false;
        }
    }
}