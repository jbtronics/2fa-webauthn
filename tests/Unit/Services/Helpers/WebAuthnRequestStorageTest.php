<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services\Helpers;

use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebAuthnRequestStorageTest extends TestCase
{
    public function testNothingStoredReturnsNull(): void
    {
        $storage = Factory::requestStorage();

        self::assertNull($storage->getActiveAuthRequest());
        self::assertNull($storage->getActiveRegistrationRequest());
    }

    public function testAuthRequestRoundTrip(): void
    {
        $storage = Factory::requestStorage();
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: 'localhost',
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            timeout: 60000,
        );

        $storage->setActiveAuthRequest($options);
        $restored = $storage->getActiveAuthRequest();

        self::assertNotNull($restored);
        self::assertSame($options->challenge, $restored->challenge);
        self::assertSame('localhost', $restored->rpId);
        self::assertSame(60000, $restored->timeout);
        self::assertNull($storage->getActiveRegistrationRequest(), 'auth and registration requests are stored separately');
    }

    public function testRegistrationRequestRoundTrip(): void
    {
        $storage = Factory::requestStorage();
        $options = PublicKeyCredentialCreationOptions::create(
            rp: Factory::webauthnProvider()->getPublicKeyCredentialRpEntity(),
            user: (new TestUser())->getWebAuthnUser(),
            challenge: random_bytes(32),
        );

        $storage->setActiveRegistrationRequest($options);
        $restored = $storage->getActiveRegistrationRequest();

        self::assertNotNull($restored);
        self::assertSame($options->challenge, $restored->challenge);
        self::assertSame('alice-id', $restored->user->id);
        self::assertSame('localhost', $restored->rp->id);
        self::assertSame('', $restored->rp->name, 'the RP name serialized as the RP ID is blanked again');
        self::assertNull($storage->getActiveAuthRequest());
    }

    public function testSettingNullClearsTheRequest(): void
    {
        $storage = Factory::requestStorage();
        $storage->setActiveAuthRequest(PublicKeyCredentialRequestOptions::create(challenge: random_bytes(32)));

        $storage->setActiveAuthRequest(null);

        self::assertNull($storage->getActiveAuthRequest());
    }
}
