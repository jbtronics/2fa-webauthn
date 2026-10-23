<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Functional\App;

use Jbtronics\TFAWebauthn\TFAWebauthnBundle;
use Psr\Log\NullLogger;
use Scheb\TwoFactorBundle\SchebTwoFactorBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * Minimal application using the bundle with its default configuration.
 * The @TFAWebauthn twig namespace is deliberately not configured here: the bundle has to register it itself.
 */
final class TestKernel extends Kernel implements CompilerPassInterface
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SecurityBundle(),
            new TwigBundle(),
            new SchebTwoFactorBundle(),
            new TFAWebauthnBundle(),
        ];
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/tfa-webauthn-tests/'.Kernel::VERSION.'/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/tfa-webauthn-tests/'.Kernel::VERSION.'/log';
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 's3cr3t',
            'test' => true,
            'http_method_override' => false,
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            // The template uses the trans filter
            'translator' => ['enabled' => true, 'fallbacks' => ['en']],
            'property_info' => ['with_constructor_extractor' => true],
        ]);
        $container->extension('security', [
            'providers' => ['memory' => ['memory' => ['users' => ['alice' => ['password' => 'x']]]]],
            'firewalls' => ['main' => ['two_factor' => ['auth_form_path' => '2fa_login', 'check_path' => '2fa_login_check']]],
        ]);
        $container->extension('scheb_two_factor', ['security_tokens' => [UsernamePasswordToken::class]]);
        $container->extension('tfa_webauthn', ['enabled' => true, 'rpName' => 'Functional', 'rpID' => 'localhost']);

        // Keep the failed authentication logs out of the test output
        $container->services()->set('logger', NullLogger::class);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('2fa_login', '/2fa');
        $routes->add('2fa_login_check', '/2fa_check');
    }

    /**
     * Make the bundle services public, so the tests can fetch them.
     */
    public function process(ContainerBuilder $container): void
    {
        foreach ($container->getDefinitions() as $id => $definition) {
            if (str_starts_with($id, 'jbtronics_webauthn_tfa.')) {
                $definition->setPublic(true);
            }
        }
    }
}
