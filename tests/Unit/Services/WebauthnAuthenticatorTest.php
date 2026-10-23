<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services;

use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebauthnAuthenticatorTest extends TestCase
{
    public function testGenerateAuthenticationRequest(): void
    {
        $user = new TestUser([Factory::credentialSource('key-1'), Factory::credentialSource('key-2')]);

        $request = Factory::authenticator($user, Factory::requestStack('https://example.com/2fa'))->generateAuthenticationRequest($user);

        self::assertSame(32, \strlen($request->challenge));
        self::assertSame('localhost', $request->rpId);
        self::assertSame(60000, $request->timeout);
        self::assertSame(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED, $request->userVerification);
        self::assertSame(['key-1', 'key-2'], array_map(static fn ($descriptor) => $descriptor->id, $request->allowCredentials));
        self::assertSame('https://example.com', $request->extensions->get('appid')->value);
    }

    public function testEveryRequestHasAFreshChallenge(): void
    {
        $user = new TestUser();
        $authenticator = Factory::authenticator($user);

        self::assertNotSame(
            $authenticator->generateAuthenticationRequest($user)->challenge,
            $authenticator->generateAuthenticationRequest($user)->challenge,
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideInvalidResponses(): iterable
    {
        yield 'not JSON' => ['not json', 'Unable to load JSON data'];
        yield 'unknown credential' => [
            '{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0In0","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"AAAA"}}',
            'No credential source found',
        ];
    }

    #[DataProvider('provideInvalidResponses')]
    public function testInvalidResponsesAreRejected(string $response, string $expectedLog): void
    {
        $logger = new class extends AbstractLogger {
            /** @var list<string> */
            public array $messages = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->messages[] = (string) $message;
            }
        };
        $user = new TestUser([Factory::credentialSource('known-key')]);
        $authenticator = Factory::authenticator($user, logger: $logger);

        self::assertFalse($authenticator->checkAuthenticationResponse($user, $authenticator->generateAuthenticationRequest($user), $response));
        self::assertCount(1, $logger->messages);
        self::assertStringContainsString($expectedLog, $logger->messages[0]);
    }

    public function testInvalidResponseWithoutLogger(): void
    {
        $user = new TestUser();
        $authenticator = Factory::authenticator($user);

        self::assertFalse($authenticator->checkAuthenticationResponse($user, $authenticator->generateAuthenticationRequest($user), 'not json'));
    }
}
