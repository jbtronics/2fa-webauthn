<?php

namespace jbtronics\TFAWebauthn\Model\Legacy;

/**
 * This interface is used to describe U2F key registrations which can be used for backwards compatibility.
 * If you have a legacy U2F key, you can implement this interface to allow users to use it for the new WebAuthn system.
 * This interface definition is based on TwoFactorKeyInterface from R/U2FTwoFactorBundle and therefore has no typing
 */
interface LegacyU2FKeyInterface
{
    /**
     * @return string
     */
    public function getKeyHandle();

    /**
     * @return string
     */
    public function getPublicKey();

    /**
     * @return string
     */
    public function getCertificate();

    /**
     * @return string
     */
    public function getCounter();
}