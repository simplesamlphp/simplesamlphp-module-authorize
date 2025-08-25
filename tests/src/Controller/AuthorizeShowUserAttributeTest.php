<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\authorize\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Module\authorize\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "authorize" module.
 *
 * @package SimpleSAML\Test
 */
class AuthorizeShowuserAttributeTest extends TestCase
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected Configuration $config;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected string $stateId;


    /**
     * Set up for each test.
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'baseurlpath' => 'https://example.org/simplesaml',
                'module.enable' => ['authorize' => true],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $state = [
            'StateId' => 'SomeState',
            'Source' => ['auth' => 'test'],
            'authprocAuthorize_ctx' => 'example',
            'authprocAuthorize_user_attribute' => 'shown_user_attribute',
        ];
        $this->stateId = Auth\State::saveState($state, 'authorize:Authorize');

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that a valid requests results in a HTTP/403 Forbidden page with translated messages
     * @return void
     * @throws \Exception
     */
    public function testValidRequest()
    {
        $request = Request::create(
            '/',
            'GET',
            ['StateId' => $this->stateId],
        );
        $session = Session::getSessionFromRequest();

        $c = new Controller\Authorize($this->config, $session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->forbidden($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isForbidden());
        $this->assertEquals('shown_user_attribute', $response->data['user_attribute']);
    }
}
