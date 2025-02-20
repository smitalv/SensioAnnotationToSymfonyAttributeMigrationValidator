<?php

declare(strict_types = 1);


use Doctrine\Common\Annotations\Reader;
use ReflectionClass;
use ReflectionMethod;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Yaml\Yaml;

#[AsCommand(name: 'app:validate-security-annotations')]
class ScanSecurityAnnotationsCommand extends Command
{
    private RouterInterface $router;
    private Reader $annotationReader;

    public function __construct(RouterInterface $router, Reader $annotationReader)
    {
        parent::__construct();

        $this->router = $router;
        $this->annotationReader = $annotationReader;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $outputFile = './security_annotations.yml';
        $routes = $this->router->getRouteCollection();
        $annotations = [];

        foreach ($routes as $routeName => $route) {
            $controller = $route->getDefault('_controller');
            if (!$controller) {
                continue;
            }

            [$controllerClass, $method] = explode('::', $controller);

            try {
                if (!isset($annotations[$controllerClass])) {
                    /** @var class-string $controllerClass */
                    $reflectionClass = new ReflectionClass($controllerClass);
                    $classSecurityAnnotations = $this->getClassSecurityAnnotations($reflectionClass);

                    if (!empty($classSecurityAnnotations)) {
                        $annotations[$controllerClass]['class_security'] = $classSecurityAnnotations;
                    }
                }

                $reflectionMethod = new ReflectionMethod($controllerClass, $method);
                $methodAnnotations = $this->getMethodSecurityAnnotations($reflectionMethod);

                if (!empty($methodAnnotations)) {
                    foreach ($methodAnnotations as $securityExpression) {
                        if (is_array($securityExpression)) {
                            $annotations[$controllerClass]['methods'][$method][] = [
                                'route' => $routeName,
                                'method_security' => $securityExpression,
                            ];
                        }
                    }
                }
            } catch (\ReflectionException $e) {
                $output->writeln(
                    "Skipping route $routeName: " . $e->getMessage()
                );
            }
        }

        file_put_contents(
            $outputFile,
            Yaml::dump($annotations, 4, 2)
        );

        $output->writeln(
            "Security annotations have been saved to $outputFile"
        );

        return Command::SUCCESS;
    }

    /**
     * @param ReflectionClass<object> $reflectionClass
     * @return array<int, mixed>
     */
    private function getClassSecurityAnnotations(ReflectionClass $reflectionClass): array
    {
        return $this->extractSecurityExpressions([
            ...$this->annotationReader->getClassAnnotations($reflectionClass),
            ...$reflectionClass->getAttributes(IsGranted::class),
            ...$reflectionClass->getAttributes(Security::class),
        ]);
    }

    /**
     * @return array<int, mixed>
     */
    private function getMethodSecurityAnnotations(ReflectionMethod $reflectionMethod): array
    {
        return $this->extractSecurityExpressions([
            ...$this->annotationReader->getMethodAnnotations($reflectionMethod),
            ...$reflectionMethod->getAttributes(IsGranted::class),
            ...$reflectionMethod->getAttributes(Security::class),
        ]);
    }

    /**
     * @param array<int, mixed> $annotations
     * @return array<int, mixed>
     */
    private function extractSecurityExpressions(array $annotations): array
    {
        $expressions = [];

        foreach ($annotations as $annotation) {
            if ($annotation instanceof Security) {
                $expressions = array_merge($expressions, $this->extractIsGrantedParams($annotation->getExpression()));
            } elseif ($annotation instanceof \ReflectionAttribute) {
                $instance = $annotation->newInstance();

                if ($instance instanceof IsGranted) {
                    $expressions[] = [
                        'attribute' => $instance->attribute,
                        'subject' => $instance->subject,
                    ];
                } elseif ($instance instanceof Security) {
                    $expressions = array_merge($expressions, $this->extractIsGrantedParams($instance->getExpression()));
                }
            }
        }

        return $expressions;
    }

    /**
     * @return array<int, mixed>
     */
    private function extractIsGrantedParams(string $expression): array
    {
        $params = [];

        if (preg_match_all("/is_granted\('([^']+)'(?:,\s*([^')]+))?\)/", $expression, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $params[] = [
                    'attribute' => $match[1],
                    'subject' => $match[2] ?? null,
                ];
            }
        }

        return $params;
    }
}
