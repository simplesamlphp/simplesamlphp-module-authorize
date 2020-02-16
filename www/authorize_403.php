<?php
/**
 * Show a 403 Forbidden page about not authorized to access an application.
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new Error\BadRequest('Missing required StateId query parameter.');
}
$state = Auth\State::loadState($_REQUEST['StateId'], 'authorize:Authorize');

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'authorize:authorize_403.php');
if (isset($state['Source']['auth'])) {
    $t->data['logoutURL'] = Module::getModuleURL(
        'core/authenticate.php',
        ['as' => $state['Source']['auth']]
    ) . "&logout";
}
if (isset($state['authprocAuthorize_reject_msg'])) {
    $t->data['reject_msg'] = $state['authprocAuthorize_reject_msg'];
}
header('HTTP/1.0 403 Forbidden');
$t->send();
