# Upgrade guide

## From 3.x to 4.0

### Requirements

| Dependency              | 3.x                   | 4.0                   |
|-------------------------|-----------------------|-----------------------|
| PHP                     | 8.2+                  | 8.2 – 8.5             |
| Symfony                 | 6.x, 7.x, 8.x         | **7.4 or 8.x**        |
| scheb/2fa-bundle        | 6.x, 7.x, 8.x         | **7.x or 8.x**        |
| web-auth/webauthn-lib   | 5.2+                  | **5.3.7+**            |

- Symfony 6.4 and 7.0–7.3 are no longer supported. Upgrade to Symfony 7.4 (LTS) first.
- scheb/2fa-bundle 6 is no longer supported. scheb/2fa-bundle 8 needs PHP 8.4, so on PHP 8.2/8.3 you stay on scheb 7.
- web-auth/webauthn-lib versions before 5.3.5 have known security advisories. 5.3.7 is the first release that
  serializes an empty relying party name as the relying party ID (see below).
- The bundle now declares the packages it actually uses (`symfony/security-bundle`, `symfony/twig-bundle`,
  `symfony/serializer`, `twig/twig`, ...). They were already installed through scheb/2fa-bundle, so this should not
  pull in anything new.

### `CredentialRecord` instead of `PublicKeyCredentialSource`

web-auth/webauthn-lib 5.3 deprecates `PublicKeyCredentialSource` (removed in 6.0) in favour of `CredentialRecord`.
The bundle now uses `CredentialRecord` everywhere:

- `TFAWebauthnRegistrationHelper::checkRegistrationResponse()` returns a `CredentialRecord`.
- `TwoFactorInterface::getWebauthnKeys()` is documented as `iterable<CredentialRecord>`.
- `UserPublicKeyCredentialSourceRepository` returns `CredentialRecord` instances (legacy U2F keys included).

Make your key entity extend `CredentialRecord` (the webauthn Symfony bundle 5.3 ships its Doctrine mapping) and
type `fromRegistration()` with it. The database columns are the same, no migration is needed:

```diff
-use Webauthn\PublicKeyCredentialSource as BasePublicKeyCredentialSource;
+use Webauthn\CredentialRecord;

-class WebAuthnKey extends BasePublicKeyCredentialSource
+class WebAuthnKey extends CredentialRecord
 {
-    public static function fromRegistration(BasePublicKeyCredentialSource $registration): self
+    public static function fromRegistration(CredentialRecord $registration): self
```

Entities still extending `PublicKeyCredentialSource` keep working on webauthn-lib 5.x (it extends
`CredentialRecord`), but trigger a deprecation at every login and will break with webauthn-lib 6.

### Relying party name and icon

- The relying party name is deprecated by web-auth/webauthn-lib 5.3. When `rpID` is configured, the bundle no longer
  sends `rpName`: browsers show the `rpID` (your domain) in the authenticator prompt instead. `rpName` is still used
  when `rpID` is not set.
- The `rpIcon` option is deprecated and ignored (it had no effect since webauthn-lib 5.1).
- `WebauthnProvider::__construct()` no longer takes an `$rpIcon` argument.

### Classes are final

All services, `Configuration`, `TFAWebauthnExtension` and `WebsafeBase64` are now `final`. If you extended one of
them, decorate the service instead, or implement the interfaces:

- `WebauthnAuthenticator` → implement `WebauthnAuthenticatorInterface` and decorate `jbtronics_webauthn_tfa.webauthn_authenticator`.
- `WebauthnFormRenderer` → implement scheb's `TwoFactorFormRendererInterface` and decorate `jbtronics_webauthn_tfa.form_renderer`.

`TwoFactorProvider` and `WebauthnFormRenderer` now accept the interfaces (`TwoFactorFormRendererInterface`,
`WebauthnAuthenticatorInterface`) instead of the concrete classes, so decorated services can be injected.

### `LegacyU2FKeyInterface` is typed

The methods now have native return types. Update your legacy U2F key entity:

```diff
-public function getKeyHandle()
+public function getKeyHandle(): string
-public function getPublicKey()
+public function getPublicKey(): string
-public function getCertificate()
+public function getCertificate(): string
-public function getCounter()
+public function getCounter(): int
```

### Other signature changes

- `WebauthnAuthenticator::generateAuthenticationRequest()` requires a `TwoFactorInterface` user (it used to accept
  `null` and throw a `LogicException`), matching `WebauthnAuthenticatorInterface`.
- `PSRRequestHelper::getCurrentRequestAsPSR7()` returns `?ServerRequestInterface` instead of `?Nyholm\Psr7\ServerRequest`.
- `UserPublicKeyCredentialSourceRepository::findAll*()` return a list (keys are not preserved any more).
- `WebsafeBase64::decodeToBinary()` throws an `InvalidArgumentException` on invalid input.
- `WebAuthnRequestStorage::setActiveAuthRequest(null)` / `setActiveRegistrationRequest(null)` now remove the stored
  request from the session.

### Configuration

- `tfa_webauthn.enabled` must be a boolean.
- `tfa_webauthn.timeout` must be at least 1.

### Behaviour changes and fixes

- The default template `@TFAWebauthn/Authentication/form.html.twig` now works out of the box: the bundle registers its
  `templates/` directory as the `@TFAWebauthn` Twig namespace. If you added a `twig.paths` entry for it as a
  workaround, you can remove it.
- A response that is valid JSON but not a WebAuthn credential (e.g. `{"foo":"bar"}`) is now rejected (authentication
  fails, registration throws a `RuntimeException`) instead of crashing with a PHP warning.
- The configured COSE algorithms are now actually used to verify signatures. Before, only ES256 and RS256 were
  accepted at login, so keys registered with another algorithm (ES384, ES512, RS384/512, PS256/384/512, EdDSA) could
  not authenticate. EdDSA needs the `sodium` extension (enabled by default in PHP).
- The registration request no longer offers the non-standard `Ed256` / `Ed512` algorithms (-260 / -261), which the
  login could not verify anyway.
- `TwoFactorProvider` implements `needsPreparation()` (returns `false`), ahead of scheb/2fa-bundle 9.
