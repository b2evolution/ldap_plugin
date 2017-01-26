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
	var $version = '6.7.9';
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


	/**
	 * Define some dependencies.
	 *
	 * @see Plugin::GetDependencies()
	 * @return array
	 */
	function GetDependencies()
	{
		return array(
				'requires' => array(
					'app_min' => '6.6.6-stable',
				),
				'recommends' => array(
					'app_min' => '6.7.0-alpha',
				),
			);
	}


	function GetDefaultSettings( & $params )
	{
		global $Settings, $app_version;

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
				'type' => version_compare( $app_version, '6.6.5', '>' ) ? 'array:array:string' : 'array',
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
					'encoding' => array(
						'label' => T_('Data encoding'),
						'note' => sprintf( T_('Data encoding of the LDAP server if it is not UTF-8. E.g. %s'), 'ISO-8859-1, UTF-16, KOI8-R, CP1250.' ),
						'size' => 10,
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
					'expand_pics' => array(
						'label' => T_('Expand profile pictures to a square'),
						'note' => T_('This will add white margins to the pictures'),
						'type'  => 'checkbox',
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
						'size' => 60,
					),
					'secondary_grp_name_attribute' => array(
						'label' => T_('Secondary Groups - Name Attribute'),
						'note' => T_('Attribute to be used as teh group name.').' '.sprintf( T_('E.g. &laquo;cn&raquo;'), 'cn' ),
						'size' => 10,
					),
					'secondary_grp_name_prefix' => array(
						'label' => T_('Secondary Groups - Name Prefix'),
						'note' => T_('Only groups with this prefix will be considered.').' '.sprintf( T_('E.g. &laquo;cms_&raquo;'), '' ),
						'size' => 10,
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
	 * Define here default user settings
	 *
	 * @return array
	 */
	function GetDefaultUserSettings( & $params )
	{
		return array(
				// It is a hidden setting, Used only to remember what number of ldap settings worked on last user logging action:
				'search_set_num' => array(
					'label' => '', // keep empty to hide on used edit advanced form
					'defaultvalue' => 0, // use first settings by default
					'type' => 'string'
				),
			);
	}


	/**
	 * Check ping service URL and plugin code.
	 */
	function BeforeEnable()
	{
		if( version_compare( phpversion(), '5.3', '<' ) )
		{	// It is required for function Normalizer::normalize() of extension PECL intl >= 1.0.0 which is bundled with PHP since version 5.3
			return T_('PHP 5 >= 5.3.0 is required for this plugin.');
		}

		return true;
	}


	/**
	 * Event handler: called when a user attemps to login.
	 *
	 * This function will check if the user exists in the LDAP directory and create it locally if it does not.
	 *
	 * @param array 'login', 'pass' and 'pass_md5'
	 */
	function LoginAttempt( & $params )
	{
		global $localtimenow;
		global $Settings, $Hit, $evo_charset;

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

			// Try to find a number of a search set which was used on successful logging previous time by current user:
			$user_search_set_num = intval( $this->UserSettings->get( 'search_set_num', $local_User->ID ) );
			if( $user_search_set_num > 0 && isset( $search_sets[ $user_search_set_num ] ) )
			{	// We have found this, Reorder the array to use the successful set firstly:
				$success_search_set = $search_sets[ $user_search_set_num ];
				unset( $search_sets[ $user_search_set_num ] );
				$search_sets = array( $user_search_set_num => $success_search_set ) + $search_sets;
			}
		}
		else
			$update_mode = false;


		$this->debug_log( sprintf('LDAP plugin will attempt to login with login=<b>%s</b> / pass=<b>%s</b> / MD5 pass=<b>%s</b>', $params['login'], $params['pass'], $params['pass_md5']) );

		// ------ Loop through list of configured LDAP Servers: ------
		foreach( $search_sets as $l_id => $l_set )
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

			if( ! empty( $l_set['encoding'] ) )
			{	// Convert each input string to current server encoding:
				$exclude_encoding_fields = array( 'uid', 'mail', 'jpegphoto' );
				if( isset( $search_info[0] ) && is_array( $search_info[0] ) )
				{
					foreach( $search_info[0] as $search_info_key => $search_info_data )
					{
						if( isset( $search_info_data[0] ) && is_string( $search_info_data[0] ) &&
								! in_array( $search_info_key, $exclude_encoding_fields ) )
						{	// Convert string from LDAP server encoding to current server encoding:
							$search_info[0][ $search_info_key ][0] = convert_charset( $search_info_data[0], $l_set['encoding'], $evo_charset );
						}
					}
				}
			}

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
				$this->userfield_update_by_code( $local_User, 'roomnumber', $search_info[0]['roomnumber'][0], 'Address', 'Room Number', 'word' );
			}

			// businesscategory -> user field "businesscategory" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['businesscategory'][0]))
			{
				$this->debug_log( 'Business Category: <b>'.$search_info[0]['businesscategory'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'businesscategory', $search_info[0]['businesscategory'][0], 'About me', 'Business Category', 'text' );
			}

			// telephonenumber -> user field "officephone" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['telephonenumber'][0]))
			{
				$this->debug_log( 'Office phone: <b>'.$search_info[0]['telephonenumber'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'officephone', $search_info[0]['telephonenumber'][0], 'Phone', 'Office phone', 'phone' );
			}

			// mobile -> user field "cellphone" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['mobile'][0]))
			{
				$this->debug_log( 'Cell phone: <b>'.$search_info[0]['mobile'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'cellphone', $search_info[0]['mobile'][0], 'Phone', 'Cell phone', 'phone' );
			}

			// employeenumber -> user field "employeenumber" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['employeenumber'][0]))
			{
				$this->debug_log( 'Employee number: <b>'.$search_info[0]['employeenumber'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'employeenumber', $search_info[0]['employeenumber'][0], 'About me', 'Employee number', 'word' );
			}

			// title -> user field "title" (if not found, autocreate it in group "About me")
			if( isset($search_info[0]['title'][0]))
			{
				$this->debug_log( 'Title: <b>'.$search_info[0]['title'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'title', $search_info[0]['title'][0], 'About me', 'Title', 'word' );
				$userfield_title = $search_info[0]['title'][0]; // Use this as role for all organizations below
			}
			else
			{
				$userfield_title = '';
			}

			// departmentnumber -> join Organization with the same name (create if doesn't exist)
			if( isset($search_info[0]['departmentnumber'][0]))
			{
				$this->debug_log( 'Department Number: <b>'.$search_info[0]['departmentnumber'][0].'</b>' );
				$this->userorg_update_by_name( $local_User, $search_info[0]['departmentnumber'][0], $userfield_title );
			}

			// o -> join Organization with the same name (create if doesn't exist)
			if( isset($search_info[0]['o'][0]))
			{
				$this->debug_log( 'Organization: <b>'.$search_info[0]['o'][0].'</b>' );
				$this->userorg_update_by_name( $local_User, $search_info[0]['o'][0], $userfield_title );
			}

			// telexnumber -> user field "officefax" (if not found, autocreate it in group "Phone")
			if( isset($search_info[0]['telexnumber'][0]))
			{
				$this->debug_log( 'Office FAX: <b>'.$search_info[0]['telexnumber'][0].'</b>' );
				$this->userfield_update_by_code( $local_User, 'officefax', $search_info[0]['telexnumber'][0], 'Phone', 'Office FAX', 'phone' );
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
							$this->debug_log( 'Assigning User to existing Primary Group.' );
						}
						else
						{
							$this->debug_log( 'Group with that name does not exist...' );

							if( $new_Group = & $this->usergroup_create( $l_set['tpl_new_grp_ID'], $assign_by_value ) )
							{	// Link the user to new created group:
								$local_User->set_Group( $new_Group );
								$assigned_group = true;
								$this->debug_log( 'Assigned User to new Primary Group.' );
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

			// Remember this settings number in order use this first in next logging time by current user:
			$this->UserSettings->set( 'search_set_num', $l_id, $local_User->ID );
			$this->UserSettings->dbupdate();

			// Assign user to organizations:
			$this->userorg_assign_to_user( $local_User );

			// jpegphoto -> Save as profile pictue "ldap.jpeg" and associate with user
			if( isset($search_info[0]['jpegphoto'][0]))
			{
				$this->debug_log( 'Photo: <img src="data:image/jpeg;base64,'.base64_encode($search_info[0]['jpegphoto'][0]).'" />' );
				// Save to disk and attach to user:
				$this->userimg_attach_photo( $local_User, $search_info[0]['jpegphoto'][0], ! empty( $l_set['expand_pics'] ) );
			}

			// --- EXTRA GROUPS ---
			if( !empty( $l_set['secondary_grp_search_filter'] ) )
			{
				global $app_version;
				if( evo_version_compare( $app_version, '6.7.0-alpha' ) < 0 )
				{	// The plugin is used on b2evo 6.6
					$this->debug_log( 'Secondary groups not handled. This feature requires b2evolution v6.7.0-alpha or newer.' );
				}
				elseif( empty($l_set['secondary_grp_name_attribute']) )
				{
					$this->debug_log( 'Missing name attribute for secondary groups' );
				}
				else
				{
					$filter = str_replace( '%s', $params['login'], $l_set['secondary_grp_search_filter'] );
					$grp_name_attribute = $l_set['secondary_grp_name_attribute'];
					$this->debug_log( sprintf( 'Step 4 : Now querying for secondary groups. base_dn: <b>%s</b>, filter: <b>%s</b>, name attribue=<b>%s</b>', $l_set['secondary_grp_base_dn'], $filter, $grp_name_attribute ) );
					$search_result = @ldap_search( $ldap_conn, $l_set['secondary_grp_base_dn'], $filter, array($grp_name_attribute) );
					if( ! $search_result )
					{ // this may happen with an empty base_dn
						$this->debug_log( 'Invalid ldap_search result. No secondary groups will be assigned. Errno: '.ldap_errno($ldap_conn).' Error: '.ldap_error($ldap_conn) );
					}
					else
					{
						$search_info = ldap_get_entries($ldap_conn, $search_result);
						// $this->debug_log( 'Results returned by LDAP Server: <pre>'.var_export( $search_info, true ).'</pre>' );

						$secondary_groups = array();

						// $this->debug_log( 'Secondary groups name prefix: <pre>'.var_export( $l_set['secondary_grp_name_prefix'], true ).'</pre>' );

						// Walk through results:
						foreach( $search_info as $group_candidate )
						{
							if( is_array( $group_candidate ) && isset($group_candidate[$grp_name_attribute][0]) )
							{
								$group_candidate_cn = $group_candidate[$grp_name_attribute][0];
								if( empty($l_set['secondary_grp_name_prefix']) || strpos($group_candidate_cn, $l_set['secondary_grp_name_prefix']) === 0 )
								{	// prefix is ok
									$this->debug_log( 'Accepted Secondary Group: '.$group_candidate_cn );
									$secondary_groups[] = $group_candidate_cn;
								}
								else
								{	// prefix is NOT ok
									$this->debug_log( 'REJECTED Secondary Group: '.$group_candidate_cn );
								}
							}
						}

						// Hardcode two secondary groups:
						// $secondary_groups = array( 'Blog B members', 'Blog D Members' );
					
						$this->debug_log( 'Secondary groups to be assigned: <pre>'.var_export( $secondary_groups, true ).'</pre>' );

						// Update secondary groups for the User:
						$this->usersecgroup_update( $local_User, $secondary_groups, $l_set['tpl_new_secondary_grp_ID'] );
					}
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


	/**
	 * Add new or Update an exsisting user field by code
	 *
	 * @param object User
	 * @param string Field code
	 * @param string Field value
	 * @param string Field group name
	 * @param string Field name
	 * @param string Field type: 'text', 'word', 'email', 'number', 'phone', 'url'
	 */
	function userfield_update_by_code( & $User, $field_code, $field_value, $field_group_name, $field_name, $field_type )
	{
		$field_value = utf8_trim( $field_value );

		if( empty( $field_value ) )
		{	// Don't add an user field with empty value:
			return;
		}

		// Get user field ID by code:
		$field_ID = $this->userfield_get_by_code( $field_code, $field_group_name, $field_name, $field_type );

		if( ! $field_ID )
		{	// Some error on creating new user field, We cannot update this field:
			// Exit here:
			$this->debug_log( sprintf( 'Skip an updating of user field "%s" because new field cannot be created.', $field_name ) );
			return;
		}

		// Load all user fields:
		$User->userfields_load();

		// What to do with the field depending on field type and new value:
		// 'add', 'update', 'nothing'
		$field_action = 'add';

		if( ! empty( $User->userfields_by_code[ $field_code ] ) && is_array( $User->userfields_by_code[ $field_code ] ) )
		{	// This user field is already defined for the user
			$userfield = $User->userfields[ $User->userfields_by_code[ $field_code ][0] ];
			if( $userfield->ufdf_duplicated == 'forbidden' )
			{	// This field cannot has multiple values, Update it to new value:
				$field_action = 'update';
				$field_ID = $userfield->uf_ID;
			}
			else
			{	// Multiple values field
				$userfield_values = array();
				foreach( $User->userfields_by_code[ $field_code ] as $userfield_ID )
				{
					$userfield_values[] = $User->userfields[ $userfield_ID ]->uf_varchar;
				}
				if( in_array( $field_value, $userfield_values ) )
				{	// User already has this field with the same action, Don't add a duplicate:
					$field_action = 'nothing';
				}
			}
		}

		switch( $field_action )
		{
			case 'add':
				// Add new user field to the user it is not defined yet:
				$User->userfield_add( $field_ID, $field_value );
				$this->debug_log( sprintf( 'Add new user field "%s"', $field_code ) );
				break;

			case 'update':
				// Update user field of the user to new value:
				$User->userfield_update( $field_ID, $field_value );
				$this->debug_log( sprintf( 'Update user field "%s" to new value', $field_code ) );
				break;
		}
	}


	/**
	 * Get user field group ID by name AND Try to create new if it doesn't exist yet
	 *
	 * @param string Field code
	 * @param string Field group name
	 * @param string Field name
	 * @param string Field type: 'text', 'word', 'email', 'number', 'phone', 'url'
	 * @return integer Field ID
	 */
	function userfield_get_by_code( $field_code, $field_group_name, $field_name, $field_type )
	{
		if( is_null( $this->userfields ) )
		{	// Load all user fields in cache on first time request:
			global $DB;
			$SQL = new SQL();
			$SQL->SELECT( 'ufdf_ID, ufdf_code' );
			$SQL->FROM( 'T_users__fielddefs' );
			$this->userfields = $DB->get_assoc( $SQL->get(), 'Load all user fields in cache array of LDAP plugin' );

			// Convert all user field codes to lowercase:
			$this->userfields = array_map( 'utf8_strtolower', $this->userfields );
		}

		// Code MUST be lowercase ASCII only:
		$field_code = utf8_strtolower( $field_code );

		// Check if requested user field code already exists in DB:
		$field_ID = array_search( $field_code, $this->userfields );

		if( $field_ID === false )
		{	// No user field in DB, Try to create new:

			$field_group_ID = $this->userfield_get_group_by_name( $field_group_name );
			if( ! $field_group_ID )
			{	// Some error on creating new user field group, We cannot create new user field without group:
				// Exit here:
				$this->debug_log( sprintf( 'Skip a creating of new user field "%s" because new group "%s" cannot be created.', $field_name, $field_group_name ) );
				return;
			}

			// Load Userfield class:
			load_class( 'users/model/_userfield.class.php', 'Userfield' );

			$Userfield = new Userfield();
			$Userfield->set( 'code', $field_code );
			$Userfield->set( 'ufgp_ID', $field_group_ID );
			$Userfield->set( 'name', $field_name );
			$Userfield->set( 'type', $field_type );
			$Userfield->set( 'order', $Userfield->get_last_order( $field_group_ID ) );
			$Userfield->set( 'duplicated', 'forbidden' );
			if( $Userfield->dbinsert() )
			{	// New user field has been created
				$field_ID = $Userfield->ID;

				// Add new user field code in cache array:
				$this->userfields[ $field_ID ] = $field_code;

				$this->debug_log( sprintf( 'New user field "%s" has been created in system', $field_name ) );
			}
		}

		return $field_ID;
	}


	/**
	 * Get user field group ID by name AND Try to create new if it doesn't exist yet
	 *
	 * @param string Field group name
	 * @return integer Field group ID
	 */
	function userfield_get_group_by_name( $field_group_name )
	{
		if( is_null( $this->userfield_groups ) )
		{	// Load all user field groups in cache on first time request:
			global $DB;
			$SQL = new SQL();
			$SQL->SELECT( 'ufgp_ID, ufgp_name' );
			$SQL->FROM( 'T_users__fieldgroups' );
			$this->userfield_groups = $DB->get_assoc( $SQL->get(), 'Load all user field groups in cache array of LDAP plugin' );

			// Convert all user field group names to lowercase:
			$this->userfield_groups = array_map( 'utf8_strtolower', $this->userfield_groups );
		}

		// Check if requested user field group already exists in DB:
		$field_group_ID = array_search( utf8_strtolower( $field_group_name ), $this->userfield_groups );

		if( $field_group_ID === false )
		{	// No user field group in DB, Try to create new:

			// Load UserfieldGroup class:
			load_class( 'users/model/_userfieldgroup.class.php', 'UserfieldGroup' );

			$UserfieldGroup = new UserfieldGroup();
			$UserfieldGroup->set( 'name', $field_group_name );
			$UserfieldGroup->set( 'order', 0 );
			if( $UserfieldGroup->dbinsert() )
			{	// New user field group has been created
				$field_group_ID = $UserfieldGroup->ID;

				// Add new user field group in cache array:
				$this->userfield_groups[ $field_group_ID ] = utf8_strtolower( $field_group_name );

				$this->debug_log( sprintf( 'New user field group "%s" has been created in system', $field_group_name ) );
			}
		}

		return $field_group_ID;
	}


	/**
	 * Assign user to organization AND Try to create new organization if it doesn't exist yet
	 *
	 * @param object User
	 * @param string Organization name
	 * @param string Organization role
	 */
	function userorg_update_by_name( & $User, $org_name, $org_role = '' )
	{
		$org_name = utf8_trim( $org_name );

		if( empty( $org_name ) )
		{	// Don't update an user organization with empty name:
			return;
		}

		if( is_null( $this->userorgs ) )
		{	// Initialize array to keep what organizations should be assigned to the user:
			$this->userorgs = array();
		}

		// Get organization ID by name AND save it in array to update after user insertion:
		$org_ID = $this->userorg_get_by_name( $org_name );
		$this->userorgs[ $org_ID ] = $org_role;
	}


	/**
	 * Get organization ID by name AND Try to create new if it doesn't exist yet
	 *
	 * @param string Organization name
	 * @return integer Organization ID
	 */
	function userorg_get_by_name( $org_name )
	{
		global $app_version;

		if( is_null( $this->organizations ) )
		{	// Load all user field groups in cache on first time request:
			global $DB;
			$SQL = new SQL();
			$SQL->SELECT( 'org_ID, org_name' );
			$SQL->FROM( 'T_users__organization' );
			$this->organizations = $DB->get_assoc( $SQL->get(), 'Load all organizations in cache array of LDAP plugin' );

			// Convert all organization names to lowercase and normalize them:
			foreach( $this->organizations as $organization_ID => $organization_name )
			{
				$this->organizations[ $organization_ID ] = utf8_strtolower( Normalizer::normalize( $organization_name ) );
			}
		}

		// Check if requested organization already exists in DB:
		$org_ID = array_search( utf8_strtolower( Normalizer::normalize( $org_name ) ), $this->organizations );

		if( $org_ID === false )
		{	// No organization in DB, Try to create new:

			// Load Organization class:
			load_class( 'users/model/_organization.class.php', 'Organization' );

			$Organization = new Organization();
			if( evo_version_compare( $app_version, '6.7.0-alpha' ) >= 0 )
			{	// The plugin is used on b2evo 6.7+
				$Organization->set( 'owner_user_ID', '1' );
			}
			$Organization->set( 'name', $org_name );
			if( $Organization->dbinsert() )
			{	// New organization has been created
				$org_ID = $Organization->ID;

				// Add new organization in cache array:
				$this->organizations[ $org_ID ] = utf8_strtolower( Normalizer::normalize( $org_name ) );

				$this->debug_log( sprintf( 'New organization "%s" has been created in system', $org_name ) );
			}
		}

		return $org_ID;
	}


	/**
	 * Assign user to organizations
	 *
	 * @param object User
	 */
	function userorg_assign_to_user( & $User )
	{
		if( empty( $User->ID ) || empty( $this->userorgs ) )
		{	// User must be created and organizations should be added
			return;
		}

		// Get current user organization to don't lose them:
		$curr_orgs = $User->get_organizations_data();
		$orgs = array();
		foreach( $curr_orgs as $curr_org_ID => $curr_org )
		{	// Keep current organizations:
			$orgs[ $curr_org_ID ] = $curr_org['role'];
		}
		foreach( $this->userorgs as $org_ID => $org_role )
		{	// Update current organizations with new:
			// NOTE: Role will be updated to new value ONLY when organization is NOT accepted yet because of perm restriction
			$orgs[ $org_ID ] = $org_role;
		}
		$org_IDs = array();
		$org_roles = array();
		foreach( $orgs as $org_ID => $org_role )
		{	// Initialize arrays to update the organizations:
			$org_IDs[] = $org_ID;
			$org_roles[] = $org_role;
		}

		// Update user's organizations in DB:
		$User->update_organizations( $org_IDs, $org_roles, true );

		// Unset this array after updating:
		unset( $this->userorgs );
	}


	/**
	 * Save to disk and attach to user
	 *
	 * @param object User (User MUST BE created in DB)
	 * @param string content of image file
	 * @param boolean TRUE - to expand photos to a square
	 */
	function userimg_attach_photo( & $User, $image_content, $expand_pics )
	{
		if( empty( $image_content ) )
		{	// No image content:
			return;
		}

		// Load FileRoot class:
		load_class( 'files/model/_fileroot.class.php', 'FileRoot' );

		// Try to create FileRoot for the user:
		$FileRootCache = & get_FileRootCache();
		$fileroot_ID = FileRoot::gen_ID( 'user', $User->ID );
		$user_FileRoot = & $FileRootCache->get_by_ID( $fileroot_ID, true );
		if( ! $user_FileRoot )
		{	// Impossible to create FileRoot for the User
			$this->debug_log( sprintf( 'FileRoot cannot be created for User #%s', $User->ID ) );
			// Exit here:
			return;
		}

		// Try to create a folder for image:
		$folder_name = 'profile_pictures'; // Folder name in user dir where we should store image file
		$image_name = 'ldap.jpg'; // File name of the image file
		$folder_path = $user_FileRoot->ads_path.$folder_name;
		$image_path = $folder_path.'/'.$image_name;
		if( ! mkdir_r( $folder_path ) )
		{	// Folder cannot be created
			$this->debug_log( sprintf( 'Cannot create image folder <b>%s</b>', $folder_path ) );
			// Exit here:
			return;
		}
		// Create/rewrite image file:
		$image_handle = fopen( $image_path, 'w+' );
		if( $image_handle === false )
		{	// File cannot be created
			$this->debug_log( sprintf( 'Cannot create image file <b>%s</b>', $image_path ) );
			// Exit here:
			return;
		}
		// Write image content in the file:
		fwrite( $image_handle, $image_content );
		fclose( $image_handle );

		// Create file object to work with image:
		$File = new File( 'user', $User->ID, $folder_name.'/'.$image_name );
		$File->rm_cache();
		$File->load_meta( true );

		if( $expand_pics )
		{	// Expand a photo to a square:
			$this->userimg_expand_to_square( $File );
		}

		// Link image file to the user:
		$LinkOwner = new LinkUser( $User );
		$File->link_to_Object( $LinkOwner );

		$avatar_file_ID = $User->get( 'avatar_file_ID' );
		if( empty( $avatar_file_ID ) )
		{	// If user has no main avatar yet then use this new one:
			$User->set( 'avatar_file_ID', $File->ID );
			$User->dbupdate();
		}
	}


	/**
	 * Expand image to a square
	 *
	 * @param object File
	 * @return boolean
	 */
	function userimg_expand_to_square( & $File )
	{
		if( ! $File->is_image() )
		{	// This must be an image:
			return false;
		}

		$Filetype = & $File->get_Filetype();
		if( ! $Filetype )
		{	// File type must be, otherwise we cannot work with this file:
			return false;
		}

		// Get image size:
		$image_size = $File->get_image_size( 'widthheight_assoc' );
		if( $image_size['width'] == $image_size['height'] )
		{	// We should not expand this image because it is already a square:
			return false;
		}

		load_funcs( 'files/model/_image.funcs.php' );

		// Load image:
		list( $err, $src_imh ) = load_image( $File->get_full_path(), $Filetype->mimetype );
		if( ! empty( $err ) )
		{	// Error on image loading:
			return false;
		}

		// Expand image to square ---- START:

		// Use max side as square size for width & height:
		$expanded_image_size = max( $image_size );

		if( $image_size['width'] > $image_size['height'] )
		{	// If width is more than height then we should center image vertically:
			$dst_x = 0;
			$dst_y = ceil( ( $expanded_image_size - $image_size['height'] ) / 2 );
		}
		else
		{	// If width is less than height then we should center image horizonatally:
			$dst_x = ceil( ( $expanded_image_size - $image_size['width'] ) / 2 );
			$dst_y = 0;
		}

		// Create canvas for new image with white background:
		$dst_imh = imagecreatetruecolor( $expanded_image_size, $expanded_image_size );
		$white_color = imagecolorallocate( $dst_imh, 255, 255, 255 );
		imagefill( $dst_imh, 0, 0, $white_color );

		if( ! @imagecopyresampled( $dst_imh, $src_imh, $dst_x, $dst_y, 0, 0, $image_size['width'], $image_size['height'], $image_size['width'], $image_size['height'] ) )
		{	// If func imagecopyresampled is not defined for example:
			return false;
		}
		// Expand image to square ---- END.

		// Save image:
		save_image( $dst_imh, $File->get_full_path(), $Filetype->mimetype );

		// Remove the old thumbnails:
		$File->rm_cache();

		return true;
	}


	/**
	 * Create new group
	 *
	 * @param integer Template group ID
	 * @param string Group name
	 * @param string Group usage: 'primary', 'secondary'
	 */
	function & usergroup_create( $template_group_ID, $group_name, $usage = 'primary' )
	{
		global $app_version;

		$GroupCache = & get_Cache( 'GroupCache' );
		if( empty($template_group_ID) )
		{
			$this->debug_log( 'No template Group ID provided!' );
		}
		elseif( ! $template_Group = $GroupCache->get_by_ID( $template_group_ID, false ) ) // COPY!! and do not halt on error
		{
			$this->debug_log( 'Template with Group ID #'.$template_group_ID.' not found!' );
		}
		else
		{	// Take a copy of the Group to use as template:
			global $DB;

			$this->debug_log( 'Using Group <b>'.$template_Group->get('name').'</b> (#'.$template_group_ID.') as template.' );

			// Create new group:
			$new_Group = new Group();

			// Get field values of the template group:
			$group_row = $DB->get_row( 'SELECT *
				 FROM T_groups
				WHERE grp_ID = '.$DB->quote( $template_group_ID ), ARRAY_A );
			foreach( $group_row as $group_field_name => $group_field_value )
			{	// Copy each value from template group to new:
				$new_Group->set( preg_replace( '/^grp_/', '', $group_field_name ), $group_field_value );
			}
			$new_Group->set( 'ID', 0 ); // unset ID (to allow inserting)
			$new_Group->set( 'name', $group_name ); // set the wanted name
			if( evo_version_compare( $app_version, '6.7.0-alpha' ) >= 0 )
			{	// The plugin is used on b2evo 6.7+
				$new_Group->set( 'usage', $usage );
			}

			// Get settings of the template group:
			$GroupSettings = & $new_Group->get_GroupSettings();
			$group_settings = $DB->get_results( 'SELECT gset_name AS name, gset_value AS value
				 FROM T_groups__groupsettings
				WHERE gset_grp_ID = '.$DB->quote( $template_group_ID ) );
			foreach( $group_settings as $group_setting )
			{	// Copy each setting from template group to new:
				$GroupSettings->set( $group_setting->name, $group_setting->value, $new_Group->ID );
			}

			// Insert new group:
			$new_Group->dbinsert();

			if( ! empty( $new_Group->ID ) )
			{
				$this->debug_log( 'Created '.$usage.' Group #'.$new_Group->ID.' <b>'.$new_Group->get( 'name' ).'</b>' );
				return $new_Group;
			}
		}

		$r = false;
		return $r;
	}


	/**
	 * Update secondary groups for User
	 *
	 * @param object User
	 * @param array Secondary groups
	 * @param integer Template secondary group ID
	 * 
	 */
	function usersecgroup_update( & $User, $secondary_groups, $template_secondary_group_ID )
	{
		global $DB;

		// It seems some transaction is not finished so two SQL queries cannot be executed without this commit:
		$DB->commit();

		// Remove the user from all previous secondary groups in order to replace them with new:
		$DB->query( 'DELETE FROM T_users__secondary_user_groups WHERE sug_user_ID = '.$User->ID,
			'Delete the User #'.$User->ID.' from old secondary groups' );

		if( empty( $secondary_groups ) )
		{	// No new secondary groups to link with user:
			return;
		}

		// Get what secondary groups exist in DB:
		$SQL = new SQL();
		$SQL->SELECT( 'grp_ID, grp_name' );
		$SQL->FROM( 'T_groups' );
		$SQL->WHERE( 'grp_usage = "secondary"' );
		$SQL->WHERE_and( 'grp_name IN ( '.$DB->quote( $secondary_groups ).' )' );
		$existing_secondary_groups = $DB->get_assoc( $SQL->get(), 'Get what secondary groups exist in DB for LDAP request' );

		// Get what secondary groups don't exist in DB and they should be created:
		$unexisting_secondary_groups = array_udiff( $secondary_groups, $existing_secondary_groups, 'strcasecmp' );

		// Save IDs of all current secondary groups in order to don't lose them:
		$new_user_secondary_group_IDs = array_keys( $existing_secondary_groups );

		if( count( $unexisting_secondary_groups ) )
		{	// Create new secondary groups:
			foreach( $unexisting_secondary_groups as $unexisting_secondary_group )
			{
				if( $new_secondary_Group = & $this->usergroup_create( $template_secondary_group_ID, $unexisting_secondary_group, 'secondary' ) )
				{	// Add this secondary group to link with user:
					$new_user_secondary_group_IDs[] = $new_secondary_Group->ID;
				}
			}
		}

		if( count( $new_user_secondary_group_IDs ) )
		{	// Link the user with secondary groups:
			$DB->query( 'INSERT INTO T_users__secondary_user_groups ( sug_user_ID, sug_grp_ID )
					VALUES ( '.$User->ID.', '.implode( ' ), ( '.$User->ID.', ', $new_user_secondary_group_IDs ).' )',
				'Link the User #'.$User->ID.' with secondary groups: '.implode( ', ', $new_user_secondary_group_IDs ) );

			$this->debug_log( 'Assign User to Secondary Groups: '.implode( ', ', $new_user_secondary_group_IDs ) );
		}
	}
}
?>