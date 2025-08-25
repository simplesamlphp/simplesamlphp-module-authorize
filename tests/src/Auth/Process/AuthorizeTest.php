<?php

/**
 * Test for the authorize:Authorize authproc filter.
 */

declare(strict_types=1);

namespace SimpleSAML\Module\authorize\Auth\Process;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\Authorize\Tests\Utils\TestableAuthorize;
use SimpleSAML\Utils;

class AuthorizeTest extends TestCase
{
    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param array $config The filter configuration.
     * @param array $request The request state.
     * @return array  The state array after processing.
     */
    private function processFilter(array $config, array $request): array
    {
        $filter = new TestableAuthorize($config, null);
        $filter->process($request);
        return $request;
    }

    /**
     * Test that having a matching attribute grants access
     *
     * @param array $userAttributes The attributes to test
     * @param bool $isAuthorized Should the user be authorized
     */
    #[DataProvider('allowScenarioProvider')]
    public function testAllowScenarios(array $userAttributes, bool $isAuthorized): void
    {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            'uid' => [
                '/^.*@example.com$/',
                '/^(user1|user2|user3)@example.edu$/',
            ],
            'schacUserStatus' => '@urn:mace:terena.org:userStatus:example.org:service:active.*@',
        ];

        $resultState = $this->processFilter($config, ['Attributes' => $userAttributes]);

        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }


    /**
     * @return array
     */
    public static function allowScenarioProvider(): array
    {
        return [
            // Should be allowed
            [['uid' => 'anything@example.com'], true],
            [['uid' => 'user2@example.edu'], true],
            [['schacUserStatus' => 'urn:mace:terena.org:userStatus:example.org:service:active.my.service'], true],
            [
                [
                    'uid' => ['wrongValue', 'user2@example.edu', 'wrongValue2'],
                    'schacUserStatus' => 'incorrectstatus',
                ],
                true,
            ],

            // Should be denied
            [['wrongAttributes' => ['abc']], false],
            [
                [
                    'uid' => [
                        'anything@example.com.wrong',
                        'wronguser@example.edu',
                        'user2@example.edu.wrong',
                        'prefixuser2@example.edu',
                    ],
                ],
                false,
            ],
        ];
    }

    /**
     * Test that having a matching attribute prevents access
     *
     * @param array $userAttributes The attributes to test
     * @param bool $isAuthorized Should the user be authorized
     */
    #[DataProvider('invertScenarioProvider')]
    public function testInvertAllowScenarios(array $userAttributes, bool $isAuthorized): void
    {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            'deny' => true,
            'uid' => [
                '/.*@students.example.edu$/',
                '/^(stu1|stu2|stu3)@example.edu$/',
            ],
            'schacUserStatus' => '@urn:mace:terena.org:userStatus:example.org:service:blocked.*@',
        ];

        $resultState = $this->processFilter($config, ['Attributes' => $userAttributes]);
        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }


    /**
     * @return array
     */
    public static function invertScenarioProvider(): array
    {
        return [
            // Should be allowed
            [['noMatch' => 'abc'], true],
            [['uid' => 'anything@example.edu'], true],

            // Should be denied
            [['uid' => 'anything@students.example.edu'], false],
            [['uid' => 'stu3@example.edu'], false],
            [['schacUserStatus' => 'urn:mace:terena.org:userStatus:example.org:service:blocked'], false],

            // Matching any of the attributes results in denial
            [
                [
                    'uid' => ['noMatch', 'abc@students.example.edu', 'noMatch2'],
                    'schacUserStatus' => 'noMatch',
                ],
                false,
            ],
        ];
    }

    /**
     * Test that having a matching attribute prevents access
     *
     * @param array $userAttributes The attributes to test
     * @param bool $isAuthorized Should the user be authorized
     */
    #[DataProvider('noregexScenarioProvider')]
    public function testDisableRegex(array $userAttributes, bool $isAuthorized): void
    {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            'regex' => false,
            'group' => [
                'CN=SimpleSAML Students,CN=Users,DC=example,DC=edu',
                'CN=All Teachers,OU=Staff,DC=example,DC=edu',
            ],
        ];

        $resultState = $this->processFilter($config, ['Attributes' => $userAttributes]);

        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }


    /**
     * @return array
     */
    public static function noregexScenarioProvider(): array
    {
        return [
            // Should be allowed
            [['group' => 'CN=SimpleSAML Students,CN=Users,DC=example,DC=edu'], true],

            //Should be denied
            [['wrongAttribute' => 'CN=SimpleSAML Students,CN=Users,DC=example,DC=edu'], false],
            [['group' => 'CN=wrongCN=SimpleSAML Students,CN=Users,DC=example,DC=edu'], false],
        ];
    }

    /**
     * Test that having a matching attribute prevents access
     *
     * @param array $userAttributes The attributes to test
     * @param bool $isAuthorized Should the user be authorized
     * @param string|null $shownUserAttribute The attribute to show
     */
    #[DataProvider('showUserAttributeScenarioProvider')]
    public function testShowUserAttribute(
        array $userAttributes,
        bool $isAuthorized,
        bool $isShowUserAttributeSet,
        ?string $shownUserAttribute,
    ): void {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            'regex' => false,
            'uid' => [
                'test',
            ],
            'show_user_attribute' => 'mail',
        ];

        $resultState = $this->processFilter($config, ['Attributes' => $userAttributes]);
        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;

        $this->assertEquals($isAuthorized, $resultAuthorized, 'Authorization behaviour does not match');
        $isShownUserAttributeInState = isset($resultState['authprocAuthorize_user_attribute']);
        $this->assertEquals(
            $isShowUserAttributeSet,
            $isShownUserAttributeInState,
            'Attribute shown behaviour does not match',
        );
        if ($isShownUserAttributeInState) {
            $isShownUserAttributeInState = $resultState['authprocAuthorize_user_attribute'];
            $this->assertEquals($shownUserAttribute, $isShownUserAttributeInState);
        }
    }

    /**
     * @return array
     */
    public static function showUserAttributeScenarioProvider(): array
    {
        return [
            // Should be allowed, and not shown
            [['uid' => 'test'], true, false, null],
            [['uid' => 'test', 'mail' => 'user@example.edu'], true, false, null],

            // Should be denied, and not shown
            [['uid' => 'anything@students.example.edu'], false, false, null],
            [['uid' => 'anything@students.example.edu', 'mail' => []], false, false, null],

            // Should be denied, and shown
            [['uid' => 'stu3@example.edu', 'mail' => 'user@example.edu'], false, true, 'user@example.edu'],
        ];
    }
}
