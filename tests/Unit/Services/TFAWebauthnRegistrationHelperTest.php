<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services;

use Cose\Algorithms;
use Jbtronics\TFAWebauthn\Services\Helpers\PSRRequestHelper;
use Jbtronics\TFAWebauthn\Services\Helpers\WebAuthnRequestStorage;
use Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper;
use Jbtronics\TFAWebauthn\Services\UserPublicKeyCredentialSourceRepository;
use Jbtronics\TFAWebauthn\Tests\Fixtures\Factory;
use Jbtronics\TFAWebauthn\Tests\Fixtures\TestUser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

final class TFAWebauthnRegistrationHelperTest extends TestCase
{
    private RequestStack $requestStack;
    private WebAuthnRequestStorage $storage;

    protected function setUp(): void
    {
        $this->requestStack = Factory::requestStack();
        $this->storage = Factory::requestStorage($this->requestStack);
    }

    public function testGenerateRegistrationRequestForCurrentUser(): void
    {
        $user = new TestUser([Factory::credentialSource('existing-key')]);

        $options = $this->createHelper($user)->generateRegistrationRequest();

        self::assertSame(32, \strlen($options->challenge));
        self::assertSame('alice-id', $options->user->id);
        self::assertSame('localhost', $options->rp->id);
        self::assertSame(60000, $options->timeout);
        self::assertSame(['existing-key'], array_map(static fn ($descriptor) => $descriptor->id, $options->excludeCredentials), 'existing keys must not be registered twice');

        $algorithms = array_map(static fn ($parameters) => $parameters->alg, $options->pubKeyCredParams);
        self::assertContains(Algorithms::COSE_ALGORITHM_ES256, $algorithms);
        self::assertContains(Algorithms::COSE_ALGORITHM_EDDSA, $algorithms);

        $stored = $this->storage->getActiveRegistrationRequest();
        self::assertNotNull($stored, 'the request is stored for validation');
        self::assertSame($options->challenge, $stored->challenge);
    }

    public function testGenerateRegistrationRequestForExplicitUser(): void
    {
        $options = $this->createHelper(null)->generateRegistrationRequest(new TestUser());

        self::assertSame('alice-id', $options->user->id);
    }

    public function testCurrentUserMustImplementTwoFactorInterface(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->createHelper(new InMemoryUser('bob', null))->generateRegistrationRequest();
    }

    public function testGenerateRegistrationRequestAsJSON(): void
    {
        $json = $this->createHelper(new TestUser())->generateRegistrationRequestAsJSON();
        $data = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($data);
        self::assertSame('localhost', $data['rp']['id']);
        self::assertArrayHasKey('challenge', $data);
        self::assertNotContains(null, $data, 'null values are skipped');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidResponses(): iterable
    {
        yield 'not JSON' => ['not json'];
    }

    #[DataProvider('provideInvalidResponses')]
    public function testCheckRegistrationResponseRejectsInvalidData(string $response): void
    {
        $helper = $this->createHelper(new TestUser());
        $helper->generateRegistrationRequest();

        $this->expectException(\RuntimeException::class);
        $helper->checkRegistrationResponse($response);
    }

    private function createHelper(?UserInterface $user): TFAWebauthnRegistrationHelper
    {
        $security = Factory::security($user);

        return new TFAWebauthnRegistrationHelper(
            60000,
            Factory::webauthnProvider(),
            $security,
            new UserPublicKeyCredentialSourceRepository($security),
            new PSRRequestHelper($this->requestStack),
            $this->storage,
        );
    }
}
