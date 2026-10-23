<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * This service provides some common services of the web-authn library which are configured by the global configuration.
 */
readonly class WebauthnProvider
{
    private SerializerInterface $serializer;

    private AuthenticatorAssertionResponseValidator $assertionResponseValidator;
    private AuthenticatorAttestationResponseValidator $attestationResponseValidator;
    private PublicKeyCredentialRpEntity $rpEntity;

    public function __construct(?string $rpID, string $rpName, ?string $rpIcon)
    {
        // Create the RP entity
        $this->rpEntity = new PublicKeyCredentialRpEntity(
            $rpName,
            $rpID,
            $rpIcon
        );

        // Create the serializer
        $attestationSupportStatementManager = new AttestationStatementSupportManager();
        $this->addAttestationTypes($attestationSupportStatementManager);

        $factory = new WebauthnSerializerFactory($attestationSupportStatementManager);
        $this->serializer = $factory->create();

        // Create the assertion response validator
        $extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

        $csmFactory = new CeremonyStepManagerFactory();
        $csmFactory->setAttestationStatementSupportManager($attestationSupportStatementManager);
        $csmFactory->setExtensionOutputCheckerHandler($extensionOutputCheckerHandler);
        $csmFactory->setAlgorithmManager($this->createAlgorithmManager());

        $creationCSM = $csmFactory->creationCeremony();
        $requestCSM = $csmFactory->requestCeremony();

        $this->assertionResponseValidator = new AuthenticatorAssertionResponseValidator($requestCSM);

        // Create the attestation response validator

        $this->attestationResponseValidator = new AuthenticatorAttestationResponseValidator($creationCSM);
    }

    private function createAlgorithmManager(): Manager
    {
        $manager = Manager::create()
            ->add(
                ES256::create(),
                ES256K::create(),
                ES384::create(),
                ES512::create(),

                RS256::create(),
                RS384::create(),
                RS512::create(),

                PS256::create(),
                PS384::create(),
                PS512::create(),
            );

        // EdDSA (Ed25519) needs the sodium extension, which is enabled by default but can be missing
        if (\extension_loaded('sodium')) {
            $manager->add(new EdDSA());
        }

        return $manager;
    }

    private function addAttestationTypes(AttestationStatementSupportManager $attestationStatementSupportManager): void
    {
        // For now, we just support the none attestations statement type as we do not request it
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
    }

    public function getPublicKeyCredentialRpEntity(): PublicKeyCredentialRpEntity
    {
        return $this->rpEntity;
    }

    public function getAuthenticatorAssertionResponseValidator(): AuthenticatorAssertionResponseValidator
    {
        return $this->assertionResponseValidator;
    }

    public function getWebauthnSerializer(): SerializerInterface
    {
        return $this->serializer;
    }

    public function getAuthenticatorAttestationResponseValidator(): AuthenticatorAttestationResponseValidator
    {
        return $this->attestationResponseValidator;
    }
}
