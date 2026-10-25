<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services;

use Jbtronics\TFAWebauthn\Services\UserPublicKeyCredentialSourceRepository;
use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\LegacyKey;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

final class UserPublicKeyCredentialSourceRepositoryTest extends TestCase
{
    public function testNoUserHasNoKeys(): void
    {
        self::assertSame([], (new UserPublicKeyCredentialSourceRepository(Factory::security()))->findAllForCurrentUser());
    }

    public function testUserWithoutTwoFactorInterfaceHasNoKeys(): void
    {
        $repository = new UserPublicKeyCredentialSourceRepository(Factory::security(new InMemoryUser('bob', null)));

        self::assertSame([], $repository->findAllForCurrentUser());
    }

    public function testMergesLegacyAndWebauthnKeys(): void
    {
        $webauthnKey = Factory::credentialSource('webauthn-key');
        $user = new TestUser(
            webauthnKeys: [$webauthnKey],
            legacyKeys: [new LegacyKey(rtrim(strtr(base64_encode("\x00legacy\xff"), '+/', '-_'), '='), base64_encode('legacy-public-key'))],
        );

        $keys = (new UserPublicKeyCredentialSourceRepository(Factory::security($user)))->findAllForCurrentUser();

        self::assertCount(2, $keys);

        // Legacy U2F keys are converted to credential sources with the decoded key handle as credential id
        self::assertSame("\x00legacy\xff", $keys[0]->publicKeyCredentialId);
        self::assertSame('legacy-public-key', $keys[0]->credentialPublicKey);
        self::assertSame('alice-id', $keys[0]->userHandle);
        self::assertSame(0, $keys[0]->counter);

        self::assertSame($webauthnKey, $keys[1]);
    }

    public function testFindOneByCredentialId(): void
    {
        $first = Factory::credentialSource('first');
        $second = Factory::credentialSource('second');
        $repository = new UserPublicKeyCredentialSourceRepository(Factory::security(new TestUser([$first, $second])));

        self::assertSame($second, $repository->findOneByCredentialId('second'));
        self::assertNull($repository->findOneByCredentialId('unknown'));
    }

    public function testLegacyPublicKeyCredentialSourceEntitiesAreStillAccepted(): void
    {
        // Entities written for 3.x extend the deprecated PublicKeyCredentialSource, which extends CredentialRecord
        $legacyEntity = new PublicKeyCredentialSource('legacy-entity', 'public-key', [], 'none', new EmptyTrustPath(), Uuid::v4(), 'public-key-data', 'alice-id', 0);
        $repository = new UserPublicKeyCredentialSourceRepository(Factory::security(new TestUser([$legacyEntity])));

        self::assertSame($legacyEntity, $repository->findOneByCredentialId('legacy-entity'));
    }

    public function testFindAllForUserEntityReturnsCurrentUserKeys(): void
    {
        $user = new TestUser([Factory::credentialSource('first')]);
        $repository = new UserPublicKeyCredentialSourceRepository(Factory::security($user));

        self::assertCount(1, $repository->findAllForUserEntity($user->getWebAuthnUser()));
    }
}
