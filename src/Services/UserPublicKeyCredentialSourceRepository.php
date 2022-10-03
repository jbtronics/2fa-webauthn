<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Helpers\WebsafeBase64;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\Security\Core\Security;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * This class provides the public key credential sources, normalize legacy U2F keys and merges U2F and Webauthn keys.
 */
class UserPublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepository
{
    private $security;

    public function __construct(Security $security)
    {
        $this->security = $security;
    }


    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $all_keys = $this->findAllForCurrentUser();

        foreach ($all_keys as $key) {
            if ($key->getPublicKeyCredentialId() === $publicKeyCredentialId) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForCurrentUser(): array
    {
        $user = $this->security->getUser();
        if(!$user instanceof TwoFactorInterface) {
            return [];
        }

        $result = [];

        //Add the legacy credentials
        foreach ($user->getLegacyU2FKeys() as $legacyU2FKey)
        {
            $result[] = new PublicKeyCredentialSource(
                WebsafeBase64::decodeToBinary($legacyU2FKey->getKeyHandle()),
                'public-key',
                [],
                'none', //dummy
                new EmptyTrustPath(), //dummy
                Uuid::fromInteger(0), //dummy,
                base64_decode($legacyU2FKey->getPublicKey()),
                $user->getWebAuthnUser()->getName(),
                0 //must be 0 to disable counter checking
            );
        }

        //Add the new webauthn keys
        $result = array_merge($result, $user->getWebAuthnKeys());

        return $result;
    }

    /**
     * @param  PublicKeyCredentialUserEntity  $publicKeyCredentialUserEntity
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return $this->findAllForCurrentUser();
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        // TODO: Implement saveCredentialSource() method.
    }
}