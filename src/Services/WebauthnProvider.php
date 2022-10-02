<?php

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithm\Manager;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\ED256;
use Cose\Algorithm\Signature\EdDSA\ED512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;

class WebauthnProvider
{
    private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository;

    private PublicKeyCredentialLoader $publicKeyCredentialLoader;

    private AuthenticatorAssertionResponseValidator $assertionResponseValidator;

    public function __construct(PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;

        $tokenBindingHandler = new TokenBindingNotSupportedHandler();
        $extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();
        $coseAlgorithmManager = new Manager();
        $this->addAlgorithms($coseAlgorithmManager);

        $this->assertionResponseValidator = new AuthenticatorAssertionResponseValidator(
            $this->publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $coseAlgorithmManager,
        );

        $attestationSupportStatementManager = new AttestationStatementSupportManager();
        $attestationObjectLoader = new AttestationObjectLoader($attestationSupportStatementManager);

        $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);
    }

    private function addAlgorithms(Manager $coseAlgorithmManager) {
        $coseAlgorithmManager->add(new ES256());
        $coseAlgorithmManager->add(new ES256K());
        $coseAlgorithmManager->add(new ES384());
        $coseAlgorithmManager->add(new ES512());

        $coseAlgorithmManager->add(new RS256());
        $coseAlgorithmManager->add(new RS384());
        $coseAlgorithmManager->add(new RS512());

        $coseAlgorithmManager->add(new PS256());
        $coseAlgorithmManager->add(new PS384());
        $coseAlgorithmManager->add(new PS512());

        $coseAlgorithmManager->add(new ED256());
        $coseAlgorithmManager->add(new ED512());
    }

    public function getAuthenticatorAssertionResponseValidator(): AuthenticatorAssertionResponseValidator
    {
        return $this->assertionResponseValidator;
    }

    public function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        return $this->publicKeyCredentialLoader;
    }
}