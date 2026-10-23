<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Security;

use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\TwoFactorProvider;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnAuthenticatorInterface;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialRequestOptions;

final class TwoFactorProviderTest extends TestCase
{
    private WebAuthnRequestStorage $storage;
    private TwoFactorFormRendererInterface $formRenderer;

    /** @var \ArrayObject<int, array{TwoFactorInterface, PublicKeyCredentialRequestOptions, string}> */
    private \ArrayObject $authenticatorCalls;

    protected function setUp(): void
    {
        $this->storage = Factory::requestStorage();
        $this->formRenderer = new class implements TwoFactorFormRendererInterface {
            public function renderForm(Request $request, array $templateVars): Response
            {
                return new Response();
            }
        };
        $this->authenticatorCalls = new \ArrayObject();
    }

    public function testBeginAuthentication(): void
    {
        $provider = $this->createProvider(true);

        self::assertTrue($provider->beginAuthentication($this->context(new TestUser())));
        self::assertFalse($provider->beginAuthentication($this->context(new TestUser(enabled: false))));
        self::assertFalse($provider->beginAuthentication($this->context(new InMemoryUser('bob', null))));
    }

    public function testNoPreparationNeeded(): void
    {
        $provider = $this->createProvider(true);

        self::assertFalse($provider->needsPreparation());
        $provider->prepareAuthentication(new TestUser());
        self::assertCount(0, $this->authenticatorCalls);
    }

    public function testFormRenderer(): void
    {
        self::assertSame($this->formRenderer, $this->createProvider(true)->getFormRenderer());
    }

    public function testValidateRejectsUsersWithoutTwoFactorInterface(): void
    {
        $this->storage->setActiveAuthRequest(PublicKeyCredentialRequestOptions::create(challenge: 'challenge'));

        self::assertFalse($this->createProvider(true)->validateAuthenticationCode(new \stdClass(), 'code'));
        self::assertCount(0, $this->authenticatorCalls);
    }

    public function testValidateWithoutActiveRequestFails(): void
    {
        self::assertFalse($this->createProvider(true)->validateAuthenticationCode(new TestUser(), 'code'));
        self::assertCount(0, $this->authenticatorCalls);
    }

    public function testValidateDelegatesToAuthenticator(): void
    {
        $user = new TestUser();
        $this->storage->setActiveAuthRequest(PublicKeyCredentialRequestOptions::create(challenge: 'challenge'));

        self::assertTrue($this->createProvider(true)->validateAuthenticationCode($user, 'code'));
        self::assertFalse($this->createProvider(false)->validateAuthenticationCode($user, 'code'));

        self::assertCount(2, $this->authenticatorCalls);
        [$calledUser, $request, $code] = $this->authenticatorCalls[0] ?? self::fail('The authenticator was not called.');
        self::assertSame($user, $calledUser);
        self::assertSame('challenge', $request->challenge);
        self::assertSame('code', $code);
    }

    private function createProvider(bool $authenticatorResult): TwoFactorProvider
    {
        $authenticator = new class($authenticatorResult, $this->authenticatorCalls) implements WebauthnAuthenticatorInterface {
            /**
             * @param \ArrayObject<int, array{TwoFactorInterface, PublicKeyCredentialRequestOptions, string}> $calls
             */
            public function __construct(private readonly bool $result, private readonly \ArrayObject $calls)
            {
            }

            public function generateAuthenticationRequest(TwoFactorInterface $user): PublicKeyCredentialRequestOptions
            {
                throw new \LogicException('Not expected to be called.');
            }

            public function checkAuthenticationResponse(TwoFactorInterface $user, PublicKeyCredentialRequestOptions $request, string $response): bool
            {
                $this->calls->append([$user, $request, $response]);

                return $this->result;
            }
        };

        return new TwoFactorProvider($this->formRenderer, $authenticator, $this->storage);
    }

    private function context(UserInterface $user): AuthenticationContextInterface
    {
        $context = $this->createStub(AuthenticationContextInterface::class);
        $context->method('getUser')->willReturn($user);

        return $context;
    }
}
