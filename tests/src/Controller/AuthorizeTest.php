<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\authorize\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\{Auth, Configuration, Error, Session};
use SimpleSAML\Module\authorize\Controller;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "authorize" module.
 *
 * @package SimpleSAML\Test
 */
class AuthorizeTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var string */
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
            'authprocAuthorize_reject_msg' => 'Test Rejected',
            'authprocAuthorize_error_url' => true,
            'authprocAuthorize_ctx' => 'example',
        ];
        $this->stateId = Auth\State::saveState($state, 'authorize:Authorize');

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that a valid requests results in a HTTP/403 Forbidden page with translated messages
     * @return void
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
    }


    /**
     * Test that a request with a missing StateId throws an exception
     * @return void
     */
    public function testMissingStateIdThrowsException()
    {
        $request = new Request();
        $session = Session::getSessionFromRequest();

        $c = new Controller\Authorize($this->config, $session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing required StateId query parameter.');

        $c->forbidden($request);
    }
}
