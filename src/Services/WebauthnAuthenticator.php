<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\KeyCollector;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RequestStack;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnAuthenticator implements WebauthnAuthenticatorInterface
{

    private U2FAppIDProvider $u2fAppIDProvider;
    private KeyCollector $keyCollector;

    protected string $requireUserVerification = "discouraged";
    protected int $timeout = 20000;
    protected WebauthnProvider $webauthnProvider;
    protected RequestStack $requestStack;


    public function __construct(U2FAppIDProvider $u2FAppIDProvider, KeyCollector $keyCollector, WebauthnProvider $webauthnProvider, RequestStack $requestStack)
    {
        $this->u2fAppIDProvider = $u2FAppIDProvider;
        $this->keyCollector = $keyCollector;
        $this->webauthnProvider = $webauthnProvider;
        $this->requestStack = $requestStack;
    }

    public function getGenerateRequest(TwoFactorInterface $user): PublicKeyCredentialRequestOptions
    {
        $allowedCredentials = $this->keyCollector->collectKeyIDsAsDescriptorArray($user);


        $challenge = random_bytes(32);
        $request = new PublicKeyCredentialRequestOptions($challenge);
        $request->setRpId('localhost');
        $request->setTimeout($this->timeout);
        $request->setUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED);

        $request->allowCredentials($allowedCredentials);

        $request->addExtension(new AuthenticationExtension('appid', $this->u2fAppIDProvider->getAppID()));

        return $request;
    }

    public function checkRequest(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $jsonResponse): bool
    {
        $publicKeyCredentialLoader = $this->webauthnProvider->getPublicKeyCredentialLoader();
        $validator = $this->webauthnProvider->getAuthenticatorAssertionResponseValidator();

        $publicKeyCredential = $publicKeyCredentialLoader->load($jsonResponse);
        $authenticatorAssertionResponse = $publicKeyCredential->getResponse();
        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            return false;
        }

        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
        $psrRequest = $psrHttpFactory->createRequest($symfonyRequest);

        $publicKeyCredentialSource = $validator->check(
            $publicKeyCredential->getRawId(),
            $authenticatorAssertionResponse,
            $request,
            $psrRequest,
            $user->getWebAuthnUser()->getName()
        );

        return true;
    }
}