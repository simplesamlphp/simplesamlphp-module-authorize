<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authorize\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the authorize module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\authorize
 */

class Authorize
{
    /**
     * Controller constructor.
     *
     * It initializes the global configuration and auth source configuration for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        protected Configuration $config,
        protected Session $session
    ) {
    }


    /**
     * Show a 403 Forbidden page about not authorized to access an application.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function forbidden(Request $request): Template
    {
        $stateId = $request->query->get('StateId', false);
        if ($stateId === false) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        /** @var array $state */
        $state = Auth\State::loadState($stateId, 'authorize:Authorize');

        $t = new Template($this->config, 'authorize:authorize_403.twig');
        if (isset($state['Source']['auth'])) {
            $t->data['source'] = $state['Source']['auth'];
        }
        if (isset($state['authprocAuthorize_reject_msg'])) {
            $t->data['reject_msg'] = $state['authprocAuthorize_reject_msg'];
        }

        if (isset($state['Source']['auth'])) {
            $t->data['LogoutURL'] = Module::getModuleURL(
                'saml/sp/login/' . urlencode($state['Source']['auth'])
            );
        }

        if (
            isset($state['authprocAuthorize_errorURL'])
            && $state['authprocAuthorize_errorURL'] === true
            && isset($state['Source']['errorURL'])
        ) {
            $errorURL = $state['Source']['errorURL'];
            $errorURL = str_replace('ERRORURL_CODE', 'AUTHORIZATION_FAILURE', $errorURL);
            if (isset($state['saml:sp:State']['core:SP'])) {
                $errorURL = str_replace('ERRORURL_RP', urlencode($state['saml:sp:State']['core:SP']), $errorURL);
            }
            if (isset($state['saml:AuthnInstant'])) {
                $errorURL = str_replace('ERRORURL_TS', $state['saml:AuthnInstant'], $errorURL);
            } else {
                $errorURL = str_replace('ERRORURL_TS', strval(time()), $errorURL);
            }
            $errorURL = str_replace('ERRORURL_TID', urlencode($this->session->getTrackID()), $errorURL);
            if (isset($state['authprocAuthorize_ctx'])) {
                $errorURL = str_replace('ERRORURL_CTX', urlencode($state['authprocAuthorize_ctx']), $errorURL);
            }
            $t->data['errorURL'] = $errorURL;
        }

        $t->setStatusCode(403);
        return $t;
    }
}
