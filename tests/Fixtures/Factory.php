<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Fixtures;

use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\U2FAppIDProvider;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\UserPublicKeyCredentialSourceRepository;
use Jbtronics\TFAWebauthn\Services\WebauthnAuthenticator;
use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Builds the bundle services by hand for unit tests.
 */
final class Factory
{
    public static function requestStack(string $uri = 'https://localhost/2fa'): RequestStack
    {
        $request = Request::create($uri);
        $request->setSession(new Session(new MockArraySessionStorage()));

        $requestStack = new RequestStack();
        $requestStack->push($request);

        return $requestStack;
    }

    public static function webauthnProvider(): WebauthnProvider
    {
        return new WebauthnProvider('localhost', 'Test');
    }

    public static function requestStorage(?RequestStack $requestStack = null): WebAuthnRequestStorage
    {
        return new WebAuthnRequestStorage($requestStack ?? self::requestStack(), self::webauthnProvider());
    }

    public static function security(?UserInterface $user = null): Security
    {
        $tokenStorage = new TokenStorage();
        if (null !== $user) {
            $tokenStorage->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        }

        $container = new Container();
        $container->set('security.token_storage', $tokenStorage);

        return new Security($container);
    }

    public static function authenticator(?UserInterface $user = null, ?RequestStack $requestStack = null, ?LoggerInterface $logger = null): WebauthnAuthenticator
    {
        $requestStack ??= self::requestStack();

        return new WebauthnAuthenticator(
            new U2FAppIDProvider($requestStack),
            new UserPublicKeyCredentialSourceRepository(self::security($user)),
            self::webauthnProvider(),
            new PSRRequestHelper($requestStack),
            60000,
            'localhost',
            $logger,
        );
    }

    public static function credentialSource(string $credentialId): CredentialRecord
    {
        return new CredentialRecord($credentialId, 'public-key', [], 'none', new EmptyTrustPath(), Uuid::v4(), 'public-key-data', 'alice-id', 0);
    }
}
