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

    /**
     * Test SP restriction functionality
     *
     * @param array $userAttributes The attributes to test
     * @param string|null $spEntityId The SP Entity ID in the state
     * @param bool $isAuthorized Should the user be authorized
     */
    #[DataProvider('spRestrictionScenarioProvider')]
    public function testSpRestriction(array $userAttributes, ?string $spEntityId, bool $isAuthorized): void
    {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            'uid' => [
                '/.*@example.com$/',
                'spEntityIDs' => [
                    'https://sp1.example.com',
                    'https://sp2.example.com',
                ],
            ],
            'group' => [
                '/^admins$/',
                'spEntityIDs' => [
                    'https://admin.example.com',
                ],
            ],
        ];

        $state = ['Attributes' => $userAttributes];
        if ($spEntityId !== null) {
            $state['saml:sp:State']['core:SP'] = $spEntityId;
        }

        $resultState = $this->processFilter($config, $state);
        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }

    /**
     * @return array
     */
    public static function spRestrictionScenarioProvider(): array
    {
        return [
            // Should be allowed - matching attribute and SP
            [['uid' => 'user@example.com'], 'https://sp1.example.com', true],
            [['uid' => 'user@example.com'], 'https://sp2.example.com', true],
            [['group' => 'admins'], 'https://admin.example.com', true],

            // Should be denied - matching attribute but wrong SP
            [['uid' => 'user@example.com'], 'https://wrong.example.com', false],
            [['group' => 'admins'], 'https://sp1.example.com', false],

            // Should be denied - no SP specified but attribute would match
            [['uid' => 'user@example.com'], null, false],
            [['group' => 'admins'], null, false],

            // Should be denied - wrong attribute regardless of SP
            [['uid' => 'user@wrong.com'], 'https://sp1.example.com', false],
            [['group' => 'users'], 'https://admin.example.com', false],
        ];
    }

    /**
     * Test mixed SP and non-SP rules
     *
     * @param array $userAttributes The attributes to test
     * @param string|null $spEntityId The SP Entity ID in the state
     * @param bool $isAuthorized Should the user be authorized
     */
    #[DataProvider('mixedRulesScenarioProvider')]
    public function testMixedSpAndNonSpRules(array $userAttributes, ?string $spEntityId, bool $isAuthorized): void
    {
        $attributeUtils = new Utils\Attributes();
        $userAttributes = $attributeUtils->normalizeAttributesArray($userAttributes);
        $config = [
            // Rule with SP restriction
            'uid' => [
                '/.*@restricted.com$/',
                'spEntityIDs' => ['https://restricted.example.com'],
            ],
            // Rule without SP restriction (should work for all SPs)
            'role' => [
                '/^admin$/',
                '/^superuser$/',
            ],
        ];

        $state = ['Attributes' => $userAttributes];
        if ($spEntityId !== null) {
            $state['saml:sp:State']['core:SP'] = $spEntityId;
        }

        $resultState = $this->processFilter($config, $state);
        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }

    /**
     * @return array
     */
    public static function mixedRulesScenarioProvider(): array
    {
        return [
            // Should be allowed - role rule matches (no SP restriction)
            [['role' => 'admin'], 'https://any.example.com', true],
            [['role' => 'superuser'], null, true],

            // Should be allowed - uid rule matches and SP is correct
            [['uid' => 'user@restricted.com'], 'https://restricted.example.com', true],

            // Should be denied - uid rule matches but SP is wrong
            [['uid' => 'user@restricted.com'], 'https://other.example.com', false],

            // Should be denied - no matching rules
            [['uid' => 'user@other.com', 'role' => 'user'], 'https://any.example.com', false],
        ];
    }
}
