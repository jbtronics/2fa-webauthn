<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Functional;

use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\TwoFactorProvider;
use Jbtronics\TFAWebauthn\Security\TwoFactor\Provider\Webauthn\WebauthnFormRenderer;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper;
use Jbtronics\TFAWebauthn\Services\UserPublicKeyCredentialSourceRepository;
use Jbtronics\TFAWebauthn\Services\WebauthnAuthenticator;
use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\Attributes\DataProvider;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderRegistry;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\ErrorHandler\ErrorHandler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

final class BundleTest extends KernelTestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        // Older Symfony 7.4 releases leave the ErrorHandler registered by FrameworkBundle::boot() behind,
        // which PHPUnit 11+ reports as risky.
        $handler = set_exception_handler(null);
        restore_exception_handler();
        if (\is_array($handler) && $handler[0] instanceof ErrorHandler) {
            restore_exception_handler();
        }
    }

    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function provideServices(): iterable
    {
        yield 'two_factor_provider' => ['jbtronics_webauthn_tfa.two_factor_provider', TwoFactorProvider::class];
        yield 'u2f_app_id_provider' => ['jbtronics_webauthn_tfa.u2f_app_id_provider', U2FAppIDProvider::class];
        yield 'form_renderer' => ['jbtronics_webauthn_tfa.form_renderer', WebauthnFormRenderer::class];
        yield 'psr_request_helper' => ['jbtronics_webauthn_tfa.psr_request_helper', PSRRequestHelper::class];
        yield 'webauthn_authenticator' => ['jbtronics_webauthn_tfa.webauthn_authenticator', WebauthnAuthenticator::class];
        yield 'registration_helper' => ['jbtronics_webauthn_tfa.registration_helper', TFAWebauthnRegistrationHelper::class];
        yield 'webauthn_request_storage' => ['jbtronics_webauthn_tfa.webauthn_request_storage', WebAuthnRequestStorage::class];
        yield 'user_public_key_source_repo' => ['jbtronics_webauthn_tfa.user_public_key_source_repo', UserPublicKeyCredentialSourceRepository::class];
        yield 'webauthn_provider' => ['jbtronics_webauthn_tfa.webauthn_provider', WebauthnProvider::class];
        yield 'registration helper alias' => [TFAWebauthnRegistrationHelper::class, TFAWebauthnRegistrationHelper::class];
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('provideServices')]
    public function testServicesAreWired(string $id, string $class): void
    {
        self::assertInstanceOf($class, self::getContainer()->get($id));
    }

    public function testProviderIsRegisteredInScheb(): void
    {
        $providers = iterator_to_array(self::service('scheb_two_factor.provider_registry', TwoFactorProviderRegistry::class)->getAllProviders());

        self::assertArrayHasKey('webauthn_two_factor_provider', $providers);
        self::assertInstanceOf(TwoFactorProvider::class, $providers['webauthn_two_factor_provider']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidAuthenticationCodes(): iterable
    {
        yield 'empty' => [''];
        yield 'not JSON' => ['not json'];
        yield 'unknown credential' => ['{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0In0","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"AAAA"}}'];
    }

    #[DataProvider('provideInvalidAuthenticationCodes')]
    public function testInvalidAuthenticationCodesAreRejected(string $code): void
    {
        $user = new TestUser([Factory::credentialSource('key-1')]);
        $this->pushRequest($user);
        $authenticator = self::service('jbtronics_webauthn_tfa.webauthn_authenticator', WebauthnAuthenticator::class);
        self::service('jbtronics_webauthn_tfa.webauthn_request_storage', WebAuthnRequestStorage::class)->setActiveAuthRequest($authenticator->generateAuthenticationRequest($user));

        self::assertFalse($this->twoFactorProvider()->validateAuthenticationCode($user, $code));
    }

    public function testRegistrationRequest(): void
    {
        $this->pushRequest(new TestUser());

        $json = self::service(TFAWebauthnRegistrationHelper::class, TFAWebauthnRegistrationHelper::class)->generateRegistrationRequestAsJSON();
        $data = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($data);
        self::assertSame('localhost', $data['rp']['id']);
        self::assertSame('Functional', $data['rp']['name']);
        self::assertSame('alice', $data['user']['name']);
        self::assertNotNull(self::service('jbtronics_webauthn_tfa.webauthn_request_storage', WebAuthnRequestStorage::class)->getActiveRegistrationRequest());
    }

    private function pushRequest(TestUser $user): Request
    {
        $request = Request::create('https://localhost/2fa');
        $request->setSession(new Session(new MockArraySessionStorage()));

        self::service('request_stack', RequestStack::class)->push($request);
        self::service('security.token_storage', TokenStorageInterface::class)->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));

        return $request;
    }

    private function twoFactorProvider(): TwoFactorProvider
    {
        return self::service('jbtronics_webauthn_tfa.two_factor_provider', TwoFactorProvider::class);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private static function service(string $id, string $class): object
    {
        $service = self::getContainer()->get($id);
        self::assertInstanceOf($class, $service);

        return $service;
    }
}
