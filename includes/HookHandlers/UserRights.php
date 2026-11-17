<?php

namespace Miraheze\MirahezeMagic\HookHandlers;

use MediaWiki\Config\Config;
use MediaWiki\Extension\CentralAuth\CentralAuthServices;
use MediaWiki\Extension\CentralAuth\Config\CAMainConfigNames;
use MediaWiki\Extension\CentralAuth\GlobalGroup\GlobalGroupAssignmentService;
use MediaWiki\Extension\CentralAuth\User\CentralAuthUser;
use MediaWiki\Extension\CentralAuth\WikiSet;
use MediaWiki\MainConfigNames;
use MediaWiki\Permissions\Hook\UserGetRightsHook;
use MediaWiki\Registration\ExtensionRegistry;
use MediaWiki\User\RestrictedUserGroupConfigReader;
use MediaWiki\User\User;
use MediaWiki\User\UserGroupManager;
use MediaWiki\User\UserRequirementsConditionCheckerFactory;

class UserRights implements UserGetRightsHook {

	public function __construct(
		private readonly Config $config,
		private readonly ExtensionRegistry $extensionRegistry,
		private readonly RestrictedUserGroupConfigReader $restrictedGroupConfigReader,
		private readonly UserGroupManager $userGroupManager,
		private readonly UserRequirementsConditionCheckerFactory $conditionCheckerFactory
	) {
	}

	/** @inheritDoc */
	public function onUserGetRights( $user, &$rights ): void {
		// Because tests that don't want to have database access complain
		if ( defined( 'MW_PHPUNIT_TEST' ) ) {
			return;
		}

		if ( $this->extensionRegistry->isLoaded( 'CentralAuth' ) ) {
			$centralUser = CentralAuthUser::getInstance( $user );
			$this->addGlobalBlockExemption( $user, $centralUser, $rights );
			$hasGlobalRight = $centralUser->hasGlobalPermission( 'editallcustomprotected' );
		} else {
			$hasGlobalRight = false;
		}
		if ( in_array( 'editallcustomprotected', $rights ) || $hasGlobalRight ) {
			$levels = $this->config->get( MainConfigNames::RestrictionLevels );
			$toAdd = array_diff(
				$levels,
				[
					'',
					'user',
					'autoconfirmed',
					'sysop'
				]
			);
			$rights = array_unique(
				array_merge(
					$rights,
					$toAdd
				)
			);
		}
	}

	private function addGlobalBlockExemption( User $user, CentralAuthUser $centralUser, array &$rights ): void {
		if ( $user->isRegistered() || in_array( 'globalblock-exempt', $rights, true ) || !$centralUser->exists() ) {
			return;
		}

		$groupManager = CentralAuthServices::getGlobalGroupManager();
		$restrictions = $this->restrictedGroupConfigReader->getConfig(
			$this->config->get( CAMainConfigNames::CentralAuthCentralWiki ),
			GlobalGroupAssignmentService::RESTRICTION_SCOPE
		);
		$now = wfTimestampNow();

		// Preserve gblock exemptions before CA attaches the local account
		foreach ( $centralUser->getGlobalGroupsWithExpiration() as $group => $expiry ) {
			if ( $expiry !== null && $expiry <= $now ) {
				continue;
			}
			if ( !in_array( 'globalblock-exempt', $groupManager->getRightsForGroup( $group ), true ) ) {
				continue;
			}

			$wikiSetId = WikiSet::getWikiSetForGroup( $group );
			if ( $wikiSetId !== 0 ) {
				$wikiSet = WikiSet::newFromID( $wikiSetId );
				if ( $wikiSet === null || !$wikiSet->inSet() ) {
					continue;
				}
			}

			if ( isset( $restrictions[$group] ) && $restrictions[$group]->continuouslyEnforced() ) {
				$checker = $this->conditionCheckerFactory->getUserRequirementsConditionChecker( $this->userGroupManager );
				if ( !$checker->recursivelyCheckCondition( $restrictions[$group]->getMemberConditions(), $user ) ) {
					continue;
				}
			}

			$rights[] = 'globalblock-exempt';
			return;
		}
	}
}
