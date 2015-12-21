<?php
/**
 * This file implements the LDAP authentification plugin.
 *
 * This file is part of the b2evolution project - {@link http://b2evolution.net/}.
 *
 * Documentation can be found at {@link http://plugins.b2evolution.net/ldap-plugin}.
 *
 * @copyright (c)2003-2015 by Francois PLANQUE - {@link http://fplanque.net/}
 * Parts of this file are copyright (c)2004-2007 by Daniel HAHLER - {@link http://thequod.de/contact}.
 *
 * @license http://b2evolution.net/about/license.html GNU General Public License (GPL)
 *
 * {@internal Open Source relicensing agreement:
 * Daniel HAHLER grants Francois PLANQUE the right to license
 * Daniel HAHLER's contributions to this file and the b2evolution project
 * under any OSI approved OSS license (http://www.opensource.org/licenses/).
 * }}
 *
 * @package plugins
 */
if( !defined('EVO_MAIN_INIT') ) die( 'Please, do not access this page directly.' );


/**
 * LDAP authentification plugin.
 *
 * It handles the event 'LoginAttempt' and tries to bind to one or several LDAP servers with 
 * the login and password of the user who is trying to login.
 *
 * If successfully bound, the plugin will query for additional info about the user.
 *
 * - A b2evolution user will be created with a random password that will never be told to the user. 
 *   This forces the user to always use a valid LDAP account for subsequent connections.
 * @todo don't show option to change passwords to LDAP users
 * - User account info will be updated at each login. A new random password will also be regenerated (just in case)
 *
 * @todo Register tools tab to search in LDAP (blueyed).
 * @todo Add setting subsets, which allow to map User object properties (dropdown) to LDAP search result entries (what's now hardcoded with "sn", "givenname" and "email")
 *
 * @package plugins
 */
class ldap_plugin extends Plugin
{
	var $version = '6.3-beta';
	var $group = 'authentication';
	var $code = 'evo_ldap_auth';
	var $priority = 50;
	var $author = 'b2evolution Group (original plugin by Daniel Hahler)';


	/**
	 * Init
	 */
	function PluginInit( & $params )
	{
		$this->name = T_('LDAP authentication');
		$this->short_desc = T_('Creates users if they could be authenticated through LDAP.');
	}


	function GetDefaultSettings()
	{
		global $Settings;

		return array(
			'fallback_grp_ID' => array(
				'label' => T_('Default primary group'),
				'type' => 'select_group',
				'note' => T_('The primary group to use for new users (can be overriden by LDAP attributes below). Select "No Group" to prevent creating new users without specifc LDAP Attributes.' ),
				'allow_none' => true,
				'defaultvalue' => isset($Settings) ? $Settings->get('newusers_grp_ID') : NULL,
			),
			'search_sets' => array(
				'label' => T_('LDAP servers to check'),
				'note' => T_('This plugin can search a username sequentially on several different LDAP servers / with different LDAP queries.'),
				'type' => 'array',
				'max_count' => 10,
				'entries' => array(
					'disabled' => array(
						'label' => T_('Disabled'),
						'defaultvalue' => 0,
						'type' => 'checkbox',
						'note' => T_('Check to disable this LDAP server.'),
					),
					'server' => array(
						'label' => T_('LDAP Server'),
						'note' => T_('Hostname with or without port').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'ldap.example.com:389' ),
						'size' => 30,
					),
					'protocol_version' => array(
						'label' => $this->T_('LDAP protocol version'),
						'type'  => 'select',
						'options' => array(
							'auto' => $this->T_('automatic'),
							'v3' => $this->T_('Version 3'),
							'v2' => $this->T_('Version 2')
						),
						'note' => $this->T_('A specific protocol version, or "auto" for "current one, then 3 and 2".'),
					),
					'rdn' => array(
						'label' => T_('RDN for binding/authenticating'),
						'note' => T_('The LDAP RDN, used to bind to the server (%s gets replaced by the user login).').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'cn=%s,ou=Users,o=Organisation' ),
						'size' => 40,
					),
					'base_dn' => array(
						'label' => T_('User Details - Base DN'),
						'note' => T_('The LDAP base DN, used as base DN to search for detailed user info after binding.').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'ou=Users,o=Organisation' ),
						'size' => 40,
					),
					'search_filter' => array(
						'label' => T_('User Details - Search filter'),
						'note' => T_('The search filter used to get information about the user (%s gets replaced by the user login).').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'uid=%s' ),
						'size' => 40,
					),
					'assign_user_to_group_by' => array(
						'label' => T_('Assign primary group by'),
						'note' => T_('LDAP search result key to assign the group by.').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'department' ),
						'size' => 30,
					),
					'tpl_new_grp_ID' => array(
						'label' => T_('Template for new primary groups'),
						'type' => 'select_group',
						'note' => T_('The group to use as template, if we create a new group. Set this to "No Group" in order not to create any new groups.'),
						'allow_none' => true,
					),
					'secondary_grp_base_dn' => array(
						'label' => T_('Secondary Groups - Base DN'),
						'note' => T_('The LDAP base DN, used as base DN to search for secondary groups.').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'ou=Groups,o=Organisation' ),
						'size' => 40,
					),
					'secondary_grp_search_filter' => array(
						'label' => T_('Secondary Groups - Search filter'),
						'note' => T_('The search filter used to get the list of groups we are interested in (filter at will) (%s gets replaced by the user login).').' '.sprintf( T_('E.g. &laquo;%s&raquo;'), 'objectClass=groupofuniquenames' ),
						'size' => 40,
					),
					'tpl_new_secondary_grp_ID' => array(
						'label' => T_('Template for new secondary groups'),
						'type' => 'select_group',
						'note' => T_('The group to use as template, if we create a new group. Set this to "No Group" in order not to create any new groups.'),
						'allow_none' => true,
					),
				),
			),

		);
	}


	/**
	 * Event handler: called when a user attemps to login.
	 *
	 * This function will check if the user exists in the LDAP directory and create it locally if it does not.
	 *
	 * @param array 'login', 'pass' and 'pass_md5'
	 */
	function LoginAttempt( $params )
	{
		global $localtimenow;
		global $Settings, $Hit;

		// Check if LDAP is available:
		if( !function_exists( 'ldap_connect' ) )
		{
			$this->debug_log( 'This PHP installation does not support LDAP functions.' );
			return false; // Login failed!
		}

		// Get ready to go through ALL LDAP Servers configured in the plugin:
		$search_sets = $this->Settings->get( 'search_sets' );
		if( empty($search_sets) )
		{
			$this->debug_log( 'No LDAP servers have been configured in the LDAP plugin settings.' );
			return false; // Login failed!
		}

		// Detect if we already have a local user with the same login:
		$UserCache = & get_Cache( 'UserCache' );
		if( $local_User = & $UserCache->get_by_login( $params['login'] ) )
		{
			$this->debug_log( 'User <b>'.$params['login'].'</b> already exists locally. We will UPDATE it with the latest LDAP attibutes.' );
			$update_mode = true;
		}
		else
			$update_mode = false;


		$this->debug_log( sprintf('LDAP plugin will attempt to login with login=<b>%s</b> / pass=<b>%s</b> / MD5 pass=<b>%s</b>', $params['login'], $params['pass'], $params['pass_md5']) );

		// ------ Loop through list of configured LDAP Servers: ------
		foreach( $search_sets as $l_id=>$l_set )
		{
			$this->debug_log( 'Step 1 : STARTING LDAP AUTH WITH SERVER #'.$l_id );

			// --- CONNECT TO SERVER ---
			$server_port = explode(':', $l_set['server']);
			$server = $server_port[0];
			$port = isset($server_port[1]) ? $server_port[1] : 389;

			if( ! empty($l_set['disabled']) )
			{
				$this->debug_log( 'Skipping disabled LDAP server &laquo;'.$server.':'.$port.'&raquo;!' );
				continue;
			}

			if( !($ldap_conn = @ldap_connect( $server, $port )) )
			{
				$this->debug_log( 'Could not connect to LDAP server &laquo;'.$server.':'.$port.'&raquo;!' );
				continue;
			}
			$this->debug_log( 'Connected to server &laquo;'.$server.':'.$port.'&raquo;..' );

			$ldap_rdn = str_replace( '%s', $params['login'], $l_set['rdn'] );
			$this->debug_log( 'Using RDN &laquo;'.$ldap_rdn.'&raquo; for binding...' );


			// --- SET PROTOCOL VERSION ---
			// Get protocol version to use:
			if( ! ldap_get_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $initial_protocol_version) )
			{
				$this->debug_log( 'Failed to get LDAP_OPT_PROTOCOL_VERSION.' );
				$initial_protocol_version = null;
			}
			$protocol_version = isset($l_set['protocol_version']) ? $l_set['protocol_version'] : 'auto'; // new setting in 2.01

			if( $protocol_version[0] == 'v' )
			{ // transform "vX" => "X"
				$try_versions = array( substr($protocol_version, 1) );
			}
			else
			{ // "auto"
				$try_versions = array(3, 2);
				if( isset($initial_protocol_version) )
				{
					array_unshift($try_versions, $initial_protocol_version);
				}
				$try_versions = array_unique($try_versions);
			}
			$this->debug_log( 'We will try protocol versions: '.implode(', ', $try_versions) );


			// --- VERIFY USER CREDENTIALS BY BINDING TO SERVER ---
			// you might use this for testing with Apache DS: if( !@ldap_bind($ldap_conn, 'uid=admin,ou=system', 'secret') )
			// Bind:
			$bound = false;
			$bind_errors = array();
			foreach( $try_versions as $try_version )
			{
				$this->debug_log( sprintf('Trying to connect with protocol version: %s / RDN: %s / pass: %s', $try_version, $ldap_rdn, $params['pass'] ) );
				ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $try_version);
				if( @ldap_bind($ldap_conn, $ldap_rdn, $params['pass']) )
				{ // Success
					$this->debug_log( 'Binding worked.' );
					$bound = true;
					break;
				}
				else
				{
					$this->debug_log( 'Binding failed. Errno: '.ldap_errno($ldap_conn).' Error: '.ldap_error($ldap_conn) );
				}
			}

			if( ! $bound )
			{
				if( isset($initial_protocol_version) )
				{	// Reset this for the next search set:
					ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $initial_protocol_version);
				}
				continue;
			}

			$this->debug_log( 'User successfully bound to server.' );


			// --- STEP 2 : TRY TO OBTAIN MORE INFO ABOUT USER ---
			// Search user info
			$filter = str_replace( '%s', $params['login'], $l_set['search_filter'] );
			$this->debug_log( sprintf( 'Step 2 : Now querying for additional user info. base_dn: <b>%s</b>, filter: <b>%s</b>', $l_set['base_dn'], $filter ) );
			$search_result = @ldap_search( $ldap_conn, $l_set['base_dn'], $filter );
			if( ! $search_result )
			{ // this may happen with an empty base_dn
				$this->debug_log( 'Invalid ldap_search result. Skipping to next search set. Errno: '.ldap_errno($ldap_conn).' Error: '.ldap_error($ldap_conn) );
				continue;
			}

			$search_info = ldap_get_entries($ldap_conn, $search_result);
			//$this->debug_log( 'Results returned by LDAP Server: <pre>'.var_export( $search_info, true ).'</pre>' );

			if( $search_info['count'] != 1 )
			{ // We have found 0 or more than 1 users, which is a problem...
				$this->debug_log( '# of entries found with search: '.$search_info['count'].' - Skipping...' );
				/*
				for ($i=0; $i<$search_info["count"]; $i++) {
					echo "dn: ". $search_info[$i]["dn"] ."<br>";
					echo "first cn entry: ". $search_info[$i]["cn"][0] ."<br>";
					echo "first email entry: ". $search_info[$i]["mail"][0] ."<p>";
				}
				*/
				continue;
			}
			$this->debug_log( 'User info has been found.' );

			// --- CREATE OR UPDATE USER ACCOUNT IN B2EVO ---
			if( $update_mode == false )
			{
				$this->debug_log( 'Step 3 : Creating a local user in b2evolution...' );
				$local_User = new User();
				$local_User->set( 'login', $params['login'] );
		
				$local_User->set( 'locale', locale_from_httpaccept() ); // use the browser's locale
				$local_User->set_datecreated( $localtimenow );
				// $local_User->set( 'level', 1 );
			}
			else
			{ // User exists already exists
				$this->debug_log( 'Step 3 : Updating the existing local user.' );
			}

			$this->debug_log( 'Randomize password in b2evolution DB and autoactivate user.' );
			// Generate a random password (we never want LDAP users to be able to login without a prior LDAP check) (also on update, just in case...
			$local_User->set_password( generate_random_passwd( 32 ) );  // $params['pass'] );

			$local_User->set( 'status', 'autoactivated' ); // Activate the user automatically (no email activation necessary)

			// Make some updates:

			// mail -> email:
			if( isset($search_info[0]['mail'][0]))
			{
				$local_User->set_email( $search_info[0]['mail'][0] );
			}
				
			// uid -> nickname
			if( isset($search_info[0]['uid'][0]))
			{
				$this->debug_log( 'UID: <b>'.$search_info[0]['uid'][0].'</b>' );
				$local_User->set( 'nickname', $search_info[0]['uid'][0] );
			}
			else
			{	// if not found, use login.
				$local_User->set( 'nickname', $params['login'] );
			}

			// givenname -> Firstname:
			if( isset($search_info[0]['givenname'][0]))
			{
				$this->debug_log( 'First name (givenname): <b>'.$search_info[0]['givenname'][0].'</b>' );
				$local_User->set( 'firstname', $search_info[0]['givenname'][0] );
			}

			// sn -> Lastname:
			if( isset($search_info[0]['sn'][0]))
			{
				$this->debug_log( 'Last name (sn): <b>'.$search_info[0]['sn'][0].'</b>' );
				$local_User->set( 'lastname', $search_info[0]['sn'][0] );
			}

			// roomnumber -> user field "roomnumber" (if not found, autocreate it in group "Address")
			if( isset($search_info[0]['roomnumber'][0]))
			{
				$this->debug_log( 'Room number: <b>'.$search_info[0]['roomnumber'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'roomnumber', $search_info[0]['roomnumber'][0], 'Address', 'Room Number' );
			}

			// businesscategory -> user field "businesscategory" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['businesscategory'][0]))
			{
				$this->debug_log( 'Business Category: <b>'.$search_info[0]['businesscategory'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'businesscategory', $search_info[0]['telephonenumber'][0], 'About Me', 'Business Category' );
			}

			// telephonenumber -> user field "officephone" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['telephonenumber'][0]))
			{
				$this->debug_log( 'Office phone: <b>'.$search_info[0]['telephonenumber'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'officephone', $search_info[0]['telephonenumber'][0], 'Phone', 'Office phone' );
			}

			// mobile -> user field "cellphone" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['mobile'][0]))
			{
				$this->debug_log( 'Cell phone: <b>'.$search_info[0]['mobile'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'cellphone', $search_info[0]['mobile'][0], 'Phone', 'Cell phone' );
			}

			// employeenumber -> user field "employeenumber" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['employeenumber'][0]))
			{
				$this->debug_log( 'Employee number: <b>'.$search_info[0]['employeenumber'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'employeenumber', $search_info[0]['employeenumber'][0], 'About me', 'Employee number' );
			}

			// departmentnumber -> join Organization with the same name (create if doesn't exist)
			if( isset($search_info[0]['departmentnumber'][0]))
			{
				$this->debug_log( 'Department Number: <b>'.$search_info[0]['departmentnumber'][0].'</b>' );
				// TODO: create/join organization
			}

			// o -> join Organization with the same name (create if doesn't exist)
			if( isset($search_info[0]['o'][0]))
			{
				$this->debug_log( 'Organization: <b>'.$search_info[0]['o'][0].'</b>' );
				// TODO: create/join organization
			}

			// title -> user field "title" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['title'][0]))
			{
				$this->debug_log( 'Title: <b>'.$search_info[0]['title'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'title', $search_info[0]['telephonenumber'][0], 'About Me', 'Title' );
			}

			// telexnumber -> user field "officefax" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['telexnumber'][0]))
			{
				$this->debug_log( 'Office FAX: <b>'.$search_info[0]['telexnumber'][0].'</b>' );
				// TODO: custom field
				// $local_User->userfield_update_by_code( 'officefax', $search_info[0]['telexnumber'][0], 'Phone', 'Office FAX' );
			}

			// jpegphoto -> Save as profile pictue "ldap.jpeg" and associate with user
			if( isset($search_info[0]['jpegphoto'][0]))
			{
				$this->debug_log( 'Photo: <img src="data:image/jpeg;base64,'.base64_encode($search_info[0]['jpegphoto'][0]).'" />' );
				// TODO: save to disk and attach to user
			}


			// ---- GROUP STUFF ----
			if( $update_mode == true )
			{	// Updating existing user
				$this->debug_log( 'Updating existing user: we do NOT touch the primary group.' );
				
				$local_User->dbupdate();
				$this->debug_log( 'OK -- User has been updated.' );
			}
			else
			{
				// Try to assign prilary group from the search results:
				$assigned_group = false;
				if( ! empty($l_set['assign_user_to_group_by']) )
				{
					$this->debug_log( 'Plugin is configured to assign the Primary Group by the '.$l_set['assign_user_to_group_by'].' key...' );
					if( isset($search_info[0][$l_set['assign_user_to_group_by']])
					 && isset($search_info[0][$l_set['assign_user_to_group_by']][0]) )
					{ // There is info we want to assign by
						$assign_by_value = $search_info[0][$l_set['assign_user_to_group_by']][0];
						$this->debug_log( 'User info says has '.$l_set['assign_user_to_group_by'].' = "<b>'.$assign_by_value.'</b>"' );

						$GroupCache = & get_Cache( 'GroupCache' );
						if( $users_Group = & $GroupCache->get_by_name( $assign_by_value, false ) )
						{ // A group with the users value returned exists.
							$local_User->set_Group( $users_Group );
							$assigned_group = true;
							$this->debug_log( 'Assigning User to existing Group.' );
						}
						else
						{
							$this->debug_log( 'Group with that name does not exist...' );

							if( ! $l_set['tpl_new_grp_ID'] )
							{
								$this->debug_log( 'No template for new primary groups is configured -> NOT creating a new group.' );
							}
							else
							{ // We want to create a new group matching the assign-by info
								$this->debug_log( 'Template for new primary groups is configured...' );

								if( ! $new_Group = $GroupCache->get_by_ID( $l_set['tpl_new_grp_ID'], false ) ) // COPY!! and do not halt on error
								{
									$this->debug_log( 'Template with Group ID #'.$l_set['tpl_new_grp_ID'].' not found!' );
								}
								else
								{ // take a copy of the Group to use as template
									// TODO: should be use "clone" to make sure we clone the object?
									// TODO: duplication doesn't seem to work, for example group level or can use API are not duplicated
									$this->debug_log( 'Using Group <b>'.$new_Group->get('name').'</b> (#'.$l_set['tpl_new_grp_ID'].') as template.' );
									$new_Group->set( 'ID', 0 ); // unset ID (to allow inserting)
									$new_Group->set( 'name', $assign_by_value ); // set the wanted name
									$new_Group->dbinsert();
									$this->debug_log( 'Created Group <b>'.$new_Group->get('name').'</b>' );
									$this->debug_log( 'Assigned User to new Group.' );

									$local_User->set_Group( $new_Group );
									$assigned_group = true;
								}
							}
						}
					}
				}

				if( ! $assigned_group )
				{ // Default group:
					$this->debug_log( 'Falling back to default primary group...' );

					$users_Group = NULL;
					$fallback_grp_ID = $this->Settings->get( 'fallback_grp_ID' );

					if( empty($fallback_grp_ID) )
					{
						$this->debug_log( 'No default/fallback primary group configured.' );
						$this->debug_log( 'User NOT created, try next LDAP server...' );
						//Continue to next LDAP server:
						continue;
					}
					else
					{
						$GroupCache = & get_Cache( 'GroupCache' );
						$users_Group = & $GroupCache->get_by_ID($fallback_grp_ID);

						if( $users_Group )
						{ // either $this->default_group_name is not given or wrong
							$local_User->set_Group( $users_Group );
							$assigned_group = true;

							$this->debug_log( 'Using default/fallback primary group: <b>'.$users_Group->get('name').'</b>' );
						}
						else
						{
							$this->debug_log( 'Default/fallback primary group does not exist ('.$fallback_grp_ID.').' );
							$this->debug_log( 'User NOT created, try next LDAP server...' );
							//Continue to next LDAP server:
							continue;
						}
					}
				}

				$local_User->dbinsert();
				$UserCache->add( $local_User );
				$this->debug_log( 'OK -- User has been created.' );
			}


			// --- EXTRA GROUPS ---
			if( !empty( $l_set['secondary_grp_search_filter'] ) )
			{
				$filter = str_replace( '%s', $params['login'], $l_set['secondary_grp_search_filter'] );
				$this->debug_log( sprintf( 'Step 4 : Now querying for secondary groups. base_dn: <b>%s</b>, filter: <b>%s</b>', $l_set['secondary_grp_base_dn'], $filter ) );
				$search_result = @ldap_search( $ldap_conn, $l_set['secondary_grp_base_dn'], $filter, array('cn') );
				if( ! $search_result )
				{ // this may happen with an empty base_dn
					$this->debug_log( 'Invalid ldap_search result. No secondary groups will be assigned. Errno: '.ldap_errno($ldap_conn).' Error: '.ldap_error($ldap_conn) );
				}
				else
				{
					$search_info = ldap_get_entries($ldap_conn, $search_result);
					$this->debug_log( 'Results returned by LDAP Server: <pre>'.var_export( $search_info, true ).'</pre>' );
				}
			}

			if( isset($initial_protocol_version) )
			{
				ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $initial_protocol_version);
			}

			// --- CONSIDER THE LOGIN ATTEMPT TO BE SUCCESSFUL AND WE ACCEPT IT ---
			// Update this value which has been passed by REFERENCE:
			$params['pass_ok'] = true;

			return true; // Login was a success (but return "true" does not trigger anything special in b2evolution)

		}

		if( isset($initial_protocol_version) )
		{
			ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $initial_protocol_version);
		}

		return false; // Login failed!
	}


	/**
	 * We need the RAW password to bind to LDAP servers.
	 * @return true
	 */
	function LoginAttemptNeedsRawPassword()
	{
		return true;
	}
}
?>