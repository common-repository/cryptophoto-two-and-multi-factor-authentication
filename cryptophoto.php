<?php

/*
Plugin Name: CryptoPhoto
Plugin URI: https://github.com/cryptophoto/cryptophoto_wordpress
Description: This plugin enables CryptoPhoto authentication for WordPress logins.
Version: 1.20180612
Author: CryptoPhoto
Author URI: http://cryptophoto.com
License: GPL2

Copyright 2018 CryptoPhoto <support@cryptophoto.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/


  require_once("include/CryptoPhotoUsersListTable.php");
  require_once("include/CryptoPhotoUtils.php");

  // displays the CryptoPhoto authentication form after the WP login
  function cryptophoto_display_auth($username, $widget, $err, $redirect) {

    $exptime = time() + 1800; // let the duo login form expire within 1 hour
    if(isset($err) && $err) {
      $err = '<div id="login_error" style="width:320px;">'.$err.'</div>';
    } else {
      $err = "";
    }       
?><!DOCTYPE html>
  <!--[if IE 8]>
    <html xmlns="http://www.w3.org/1999/xhtml" class="ie8" <?php language_attributes(); ?>>
  <![endif]-->
  <!--[if !(IE 8) ]><!-->
    <html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
  <!--<![endif]-->
  <head>
  <meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
  <title><?php bloginfo('name'); ?> &rsaquo; <?php echo $title; ?></title>
  <?php

  wp_admin_css( 'login', true );

  do_action( 'login_enqueue_scripts' );
  do_action( 'login_head' );

  if ( is_multisite() ) {
    $login_header_url   = network_home_url();
    $login_header_title = get_current_site()->site_name;
  } else {
    $login_header_url   = __( 'https://wordpress.org/' );
    $login_header_title = __( 'Powered by WordPress' );
  }

  $login_header_url = apply_filters( 'login_headerurl', $login_header_url );
  $login_header_title = apply_filters( 'login_headertitle', $login_header_title );

  $classes = array( 'login-action-' . $action, 'wp-core-ui' );
  if ( wp_is_mobile() )
    $classes[] = 'mobile';
  if ( is_rtl() )
    $classes[] = 'rtl';
  if ( $interim_login ) {
    $classes[] = 'interim-login';
    ?>
    <style type="text/css">html{background-color: transparent;}</style>
    <?php

    if ( 'success' ===  $interim_login )
      $classes[] = 'interim-login-success';
  }
  $classes[] =' locale-' . sanitize_html_class( strtolower( str_replace( '_', '-', get_locale() ) ) );
  $classes = apply_filters( 'login_body_class', $classes, $action );
  ?>
  </head>

<body class="login <?php echo esc_attr( implode( ' ', $classes ) ); ?>">
  <div id="login">
    <h1><a href="<?php echo esc_url( $login_header_url ); ?>" title="<?php echo esc_attr( $login_header_title ); ?>" tabindex="-1"><?php bloginfo( 'name' ); ?></a></h1>
              
<?php echo $err; 

// the CryptoPhoto authentication form
?>
<form method="post" style='width:300px'>
  <?php echo $widget; ?>
  <p class="submit" style="text-align:center">
    <input type="submit" name="cp_auth" id="cp_auth" class="button-primary" value="Authenticate" tabindex="100" style="float:none" />
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>" />
    <input type="hidden" name="u" value="<?php echo esc_attr($username); ?>" />
    <input type="hidden" name="exptime" value="<?php echo esc_attr($exptime); ?>"/>
    <input type="hidden" name="uhash" value="<?php echo esc_attr(wp_hash($username.$exptime)); ?>"/>
  </p>
</form>
<?php if ( ! $interim_login ): ?>
  <p id="backtoblog"><a href="<?php echo esc_url( home_url( '/' ) ); ?>" title="<?php esc_attr_e( 'Are you lost?' ); ?>"><?php printf( __( '&larr; Back to %s' ), get_bloginfo( 'title', 'display' ) ); ?></a></p>
<?php endif; ?>

  </div>
<?php do_action( 'login_footer' ); ?>
  <div class="clear"></div>
  </body>
  </html>
<?php
  }//"
  
  // CryptoPhoto authentication
  function cryptophoto_authenticate_user($user = "", $username = "", $password = "") {

    $err = "";
    // guests are not allowed
    if($user && get_class($user) == "WP_Error") {
      error_log("WP_Error");
      return;
    } 
    else {
      // 
      if($username && $password) {

        // check for valid WP login
        $result = wp_authenticate_username_password(null, $username, $password);
        if(get_class($result) == "WP_Error") {
          return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: The password you entered for the username <strong>'.$username.'</strong> is incorrect. <a href="'.get_site_url().'/wp-login.php?action=lostpassword" title="Password Lost and Found">Lost your password</a>?'));
        }
      }
    }  

    if ( defined('XMLRPC_REQUEST') && XMLRPC_REQUEST ) {
        return; //allows the XML-RPC protocol for remote publishing
    }

    // get the CryptoPhoto settings
    $publickey = get_option("cryptophoto_publickey", "");
    $privatekey = get_option("cryptophoto_privatekey", "");
    $salt = get_option("cryptophoto_salt", "");
    $server = get_option("cryptophoto_server", "");

    // CryptoPhoto isn't set up for this certain site
    if ($publickey == "" || $privatekey == "" || $salt =="") {
        return;
    }

    // check for non-empty CryptoPhoto authentication fields
    if (isset($_POST['cp_auth']) || isset($_POST["cp_phc"])) {

      // forcefully log the current user out
      remove_action('authenticate', 'wp_authenticate_username_password', 20);
      
      if($_POST['u']) {
        
        // get the value of the hidden username variable  
        $username = $_POST["u"];
        $sig = wp_hash($_POST['u'] . $_POST['exptime']);
        $expire = intval($_POST['exptime']);
        
        if (wp_hash($_POST['uhash']) == wp_hash($sig) && time() < $expire) {
        
          // get the current user's username
          $user = get_user_by('login', $username);
          // new CryptoPhoto class instance
          $cp = new CryptoPhotoUtils($server, $privatekey, $publickey, md5($salt . $user->ID));

          // check for posted token
          if(!isset($_POST["token_selector"])) {
            $err = "Token not selected";
          }
          else {
            if((isset($_POST["token_response_field_col"]) || isset($_POST["token_response_field_row"])) && (isset($_POST["cp_phc"])) ) {
              $err = "Missing required codes. Invalid authentication";
            }
          }

          // check the post for valid token selector and CryptoPhoto codes
          if ($_POST["token_selector"] && ( ($_POST["token_response_field_row"] && $_POST["token_response_field_col"]) || $_POST["cp_phc"]) ) {
        
            // get the posted values
            $selector = $_POST["token_selector"];
            $row_code = $_POST["token_response_field_row"] ? $_POST["token_response_field_row"] : "";
            $col_code = $_POST["token_response_field_col"] ? $_POST["token_response_field_col"] : "";
            $cp_phc  = $_POST["cp_phc"] ? $_POST["cp_phc"] : "";
            $ip      = $_SERVER['REMOTE_ADDR'];
      
            // check the CryptoPhoto response
            $cp->verify_response($selector, $row_code, $col_code, $cp_phc, $ip);
            
            // codes ok, let's finally login this user
            if($cp->is_valid) {
              wp_set_auth_cookie($user->ID);
              wp_safe_redirect($_POST['redirect_to']);
              exit();
            } 

            // invalid authentication
            else {
              $cperror = $cp->error;
              if($cperror == "incorrect-retry-count") {
                $err = "";
              } else {
                $err = "Codes don't match";//'
              }              
            }
          }
        } 
        else {
          return new WP_Error('CryptoPhoto authentication_failed', __('<strong>ERROR</strong>: Failed or expired CryptoPhoto authentication'));//'
        }
      }
    }

    // check for valid username
    if (strlen($username) > 0) {
      $user = get_user_by('login', $username);
      if (!$user) {
        return;
      }

      // get the current user's ID
      $usr = new WP_User($user->ID);

      global $wp_roles;
      foreach ($wp_roles->get_names() as $r) {
        $all_roles[strtolower(before_last_bar($r))] = ucfirst(before_last_bar($r));
      }

      $cryptophoto_roles = get_option('cryptophoto_roles', $all_roles); 
      $cryptophoto_auth = false;

      if (!empty($usr->roles) && is_array($usr->roles)) {
        foreach ($usr->roles as $role) {
          if (array_key_exists(strtolower(before_last_bar($role)), $cryptophoto_roles)) {
            $cryptophoto_auth = true;
          }
        }
      }

      // get the CryptoPhoto status of a user, by ID
      $isactive = get_user_option("cryptophoto_enabled", $user->ID);
      
      // check the user's CryptoPhoto status
      $cryptophoto_auth = false;
      if ($isactive != false && $isactive == '1') {
        $cryptophoto_auth = true;
      }
      
      // Cryptophoto is enabled 
      if ($cryptophoto_auth == true) {
        // start new CryptoPhoto session
        $cp = new CryptoPhotoUtils($server, $privatekey, $publickey, md5($salt . $user->ID));
        $cp->start_session($_SERVER['REMOTE_ADDR'], true);
        $cryptophoto_auth = $cp->has_token == 'true' ? true : false;
      }
      
      if($cryptophoto_auth == false) {
        return;
      }

      // forcefully log the current user out
      remove_action('authenticate', 'wp_authenticate_username_password', 20);

      // display the CryptoPhoto authentication form
      cryptophoto_display_auth($username, $cp->get_auth_widget(), $err, $_POST['redirect_to']);
      exit();
    }
  }


  // CryptoPhoto settings page
  function cryptophoto_configuration_page() {

    $tab = "settings";    

    // set the class attribute to render the tabs active/nactive
    if(isset($_REQUEST['tab']) && strtolower($_REQUEST['tab']) == "users") {
      // users tab active
      $tab = "users";
      $class1 = 'class="nav-tab nav-tab-inactive"';
      $class2 = 'class="nav-tab nav-tab-active';
    }
    else {
      // settings tab active
      $class1 = 'class="nav-tab nav-tab-active';
      $class2 = 'class="nav-tab nav-tab-inactive"';
    }

    echo '<div class="wrap">';
    echo '<div id="icon-themes" class="icon32"><br/></div>';
    echo '<h2 class="nav-tab-wrapper">';
    echo '<a ' . $class1 . ' href="'.$_SERVER['PHP_SELF'].'?page=cryptophoto_wordpress">CryptoPhoto Settings</a>';
    echo '<a ' . $class2 . ' href="'.$_SERVER['PHP_SELF'].'?page=cryptophoto_wordpress&tab=users">CryptoPhoto Users</a></h2>';

    // render the CryptoPhoto users page 
    if ($tab == "users") {
      cp_users_list_screen_options();
      cp_users_list_page();
    } 

    // render the CryptoPhoto settings page
    else {

      $cp = new CryptoPhotoUtils("");
      $ip = $cp->get_request('https://cryptophoto.com/show_my_ip');

?>

      <form action="options.php" method="post">
        <?php settings_fields('cryptophoto_settings'); ?>
        <?php do_settings_sections('cryptophoto_settings'); ?> 
        <div style="margin:0 10px;" style="font-size:12px; font-weight:bold;">
            <div id='testconfig'> </div>
        </div>
        <p class="submit" style="margin-top:0">
          <input style="margin:15px 10px 0 10px;" name="Submit" type="submit" value="<?php esc_attr_e("Save Settings"); ?>" />
          <input style="margin:15px 10px 0 10px;" name="Wizard" type="button" onclick="return CPPluginWizard.start_wizard()" value="<?php esc_attr_e("Wizard"); ?>" />
          <input style="margin:15px 10px 0 10px;" name="Test" type="button" onclick="return testConfig()" value="<?php esc_attr_e("Test Configuration"); ?>" />
          <span id="cpspinner" class="spinner" style="float:none;margin-bottom:10px;"></span> 
        </p>
      </form>

      
      <p class='description' id='tagline-description'><strong>Note:</strong> Save your changes then click on "Test Configuration" in order to do a test CryptoPhoto API call.</p>

<script type="text/javascript">

if (typeof CPPluginWizard !== 'object') CPPluginWizard = {};

CPPluginWizard.serverip = "<?php echo $ip ?>";
CPPluginWizard.callback = function(keys) {

  if(keys.PRIVATE_KEY && keys.PUBLIC_KEY) {
    document.getElementById("cryptophoto_publickey").value = keys.PUBLIC_KEY;
    document.getElementById("cryptophoto_privatekey").value = keys.PRIVATE_KEY;
    if (!!!document.getElementById("cryptophoto_salt").value) {
      document.getElementById("cryptophoto_salt").value = guid();
    }
    testConfig();
  }

};

//Browser Support Code
function testConfig() {

  document.getElementById("cpspinner").className = "spinner is-active";

  var ajaxRequest;  // The variable that makes Ajax possible!

  try{
    // Opera 8.0+, Firefox, Safari
    ajaxRequest = new XMLHttpRequest();
  } catch (e){
    // Internet Explorer Browsers
    try{
      ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");
    } catch (e) {
      try{
        ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");
      } catch (e) {
        // Something went wrong
        return false;
      }
    }
  }

  // Create a function that will receive data sent from the server
  ajaxRequest.onreadystatechange = function() {

    if(ajaxRequest.readyState == 4 && ajaxRequest.status == 200) {
      
      document.getElementById("cpspinner").className = "spinner";

      if(ajaxRequest.responseText.indexOf('success') > -1) {
        document.getElementById("testconfig").innerHTML="CryptoPhoto plugin is configured properly. You can save your settings now.";
        document.getElementById("testconfig").setAttribute("style","color:green"); 
      }
      else if(ajaxRequest.responseText.indexOf('timestamp') > -1) {
        document.getElementById("testconfig").innerHTML="Error: Please verify that the date/time is properly set on this server.";
        document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
      else if(ajaxRequest.responseText.indexOf('ip') > -1) {
        var ip = "";
        ip = ajaxRequest.responseText.replace("ip ","");

        if (ip) { 
          ip = " (" + ip +")";
        } 
        else {
          ip = "";
        }

        document.getElementById("testconfig").innerHTML="Error: The IP of this server"+ip+" is not added to the list of allowed IPs. Check your settings in your CryptoPhoto.com account.";
        document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
      else if(ajaxRequest.responseText.indexOf('invalid') > -1) {
        document.getElementById("testconfig").innerHTML="Error: Please verify that the API keys are valid.";
       document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
      else if(ajaxRequest.responseText.indexOf('empty') > -1) {
       document.getElementById("testconfig").innerHTML="Error: Please configure and save your API keys and salt.";
       document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
      else if(ajaxRequest.responseText.indexOf('inexistent-provider') > -1) {
       document.getElementById("testconfig").innerHTML="Error: Please verify that the API keys are valid.";
       document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
      else {
        document.getElementById("testconfig").innerHTML="Error: Unknown error.";
        document.getElementById("testconfig").setAttribute("style","color:red"); 
      }
    }
  }
  var data = "action=cryptophoto_test&test=true";

  data += "&cryptophoto_publickey=" + encodeURIComponent(document.getElementById("cryptophoto_publickey").value);
  data += "&cryptophoto_privatekey=" + encodeURIComponent(document.getElementById("cryptophoto_privatekey").value);
  data += "&cryptophoto_salt=" + encodeURIComponent(document.getElementById("cryptophoto_salt").value);
  data += "&cryptophoto_server=" + encodeURIComponent(document.getElementById("cryptophoto_server").value);
  
  ajaxRequest.open("POST", ajaxurl, true);
  ajaxRequest.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
  ajaxRequest.send(data);
  return false;

}

function guid() {
  var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split(''); 
  var uuid = new Array(36), rnd=0, r;
  for (var i = 0; i < 36; i++) {
    if (i==8 || i==13 ||  i==18 || i==23) {
      uuid[i] = '';
    } else if (i==14) {
      uuid[i] = '4';
    } else {
      if (rnd <= 0x02) rnd = 0x2000000 + (Math.random()*0x1000000)|0;
      r = rnd & 0xf;
      rnd = rnd >> 4;
      uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
    }
  }
  return uuid.join('');
}

function add_script (a) {
  var b = document.createElement("script");
  b.type = "text/javascript";
  b.src = a;
  document.body.appendChild(b);
}

var server = document.getElementById("cryptophoto_server").value;
if(server.indexOf("http") > -1) {
  add_script(server+"/api/plugin/config.js");
}

</script>


<?php
      }

    echo '</div>';
  }
  

  // Process a request to check the current CryptoPhoto Plugin configuration
  function cryptophoto_process_test() {

    // user ID is set
    if(isset($_POST['test'])) {
     
      $publickey = $_POST['cryptophoto_publickey'];
      $privatekey = $_POST['cryptophoto_privatekey'];
      $salt = $_POST['cryptophoto_salt'];
      $server = $_POST['cryptophoto_server'];
     
      // check that all parameters are set
      if($publickey != "" && isset($publickey) && $privatekey != "" && isset($privatekey) && $salt != "" && isset($salt)) {

        // new CP instance
        $cp = new CryptoPhotoUtils($server, $privatekey, $publickey, md5($salt . $userid));
        $session = $cp->start_session($_SERVER['REMOTE_ADDR']);

        // new session started successfully
        if($session[0] == TRUE) {
          update_option('cryptophoto_publickey', $publickey);
          update_option('cryptophoto_privatekey', $privatekey);
          update_option('cryptophoto_salt', $salt);
          $server = $server ? $server : "https://cryptophoto.com";
          update_option('cryptophoto_server', $server);
          $result = "success";
        } 
        
        // something went wrong
        else {
          if ($session[1] == "inexistent-provider") {
            $result = "inexistent-provider";
          } else if ($session[1] == "incorrect-timestamp") {
            $result = "timestamp";
          } 
          else if (strpos($session[1],"ip-not-allowed") !== false) {
            $result = "ip " . $session[2];
          } 
          else if ($session[1] == "incorrect-signature" || $session[1] == "incorrect-api-request") {
            $result = "invalid";
          } 
          else $result = "other";
        }
      }
      else {
        $result = "empty";
      }
    }

    echo $result;
   
    die();
  }


  // blank callback function needed in cryptophoto_admin_init
  function cryptophoto_settings_text() {
      echo "<p> </p>";
  }

  // the CryptoPhoto public key text input
  function cryptophoto_settings_publickey() {
      $publickey = esc_attr(get_option('cryptophoto_publickey'));
      echo "<input id='cryptophoto_publickey' name='cryptophoto_publickey' size='40' type='text' value='$publickey' />";
      echo "<p class='description' id='tagline-description'>You CryptoPhoto API Public Key.</p>";
  }


  // the CryptoPhoto private key text input
  function cryptophoto_settings_privatekey() {
      $privatekey = esc_attr(get_option('cryptophoto_privatekey'));
      echo "<input id='cryptophoto_privatekey' name='cryptophoto_privatekey' size='40' type='text' value='$privatekey' />";
      echo "<p class='description' id='tagline-description'>You CryptoPhoto API Private Key.</p>";
  }


  // the salt text input
  function cryptophoto_settings_salt() {
      $salt = esc_attr(get_option('cryptophoto_salt'));
      echo "<input id='cryptophoto_salt' name='cryptophoto_salt' size='40' type='text' value='$salt' />";
      echo "<p class='description' id='tagline-description'>The \"Salt\" is used to create unique user IDs. It is recomended to use a random string and once set, not to change it, otherwise the CryptoPhoto settings of each of your users will be reset.</p>";
  }

  // the salt text input
  function cryptophoto_settings_server() {
      $server = esc_attr(get_option('cryptophoto_server'));
      $server = $server ? $server : "https://cryptophoto.com";
      echo "<input id='cryptophoto_server' name='cryptophoto_server' size='40' type='text' value='$server' />";
      echo "<p class='description' id='tagline-description'>Set a server url if you're using a CryptoPhoto appliance, otherwise leave this field as is.</p>";
  }

  // the user roles checkboxes
  function cryptophoto_settings_roles() {
      global $wp_roles;

      $roles = $wp_roles->get_names();
      $newroles = array();
      foreach($roles as $key=>$role) {
          $newroles[before_last_bar($key)] = before_last_bar($role);
      }

      $selected = get_option('cryptophoto_roles', $newroles);
      foreach ($wp_roles->get_names() as $role) {
        //create checkbox for each role
?>
        <input id="cryptophoto_roles" name='cryptophoto_roles[<?php echo strtolower(before_last_bar($role)); ?>]' type='checkbox' value='<?php echo before_last_bar($role); ?>' <?php if(in_array(before_last_bar($role), $selected)) echo 'checked="checked"'; ?> /> <?php echo before_last_bar($role); ?> <br />
<?php
      }//'
  }


  // validate user roles
  function cryptophoto_roles_validate($options) {
    //return empty array
    if (!is_array($options) || empty($options) || (false == $options)) {
      return array();
    }

    global $wp_roles;
    $valid_roles = $wp_roles->get_names();

    //otherwise validate each role and then return the array
    foreach ($options as $opt) {
      if (!in_array(before_last_bar($opt), $valid_roles)) {
          unset($options[before_last_bar($opt)]);
      }
    }
    return $options;
  }


  // validate publickey
  function cryptophoto_publickey_validate($publickey) {
    if (strlen($publickey) == 0) {
      add_settings_error('cryptophoto_publickey', '', 'Public Key is not valid');
      return "";
    } 
    else {
     return $publickey;
    }
  }
  

  // validate privatekey
  function cryptophoto_privatekey_validate($privatekey) {
    if (strlen($privatekey) == 0) {
        add_settings_error('cryptophoto_privatekey', '', 'Private key is not valid');
        return "";
    } 
    else {
        return $privatekey;
    }
  }


  // validate salt
  function cryptophoto_salt_validate($salt) {
      if (strlen($salt) == 0) {
          add_settings_error('cryptophoto_salt', '', 'Salt is not valid');
          return "";
      } 
      else {
          return $salt;
      }
  }

  // validate salt
  function cryptophoto_server_validate($server) {
      if (strlen($server) == 0 || !preg_match('|^http(s)?://[a-z0-9-]+(.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$|i', $server)) {
          add_settings_error('cryptophoto_server', '', 'Server is not valid');
          return "";
      } 
      else {
          return $server;
      }
  }


  // register fields to pages, settings and callbacks
  function cryptophoto_admin_init() {
      add_settings_section('cryptophoto_settings', 'Plugin Settings', 'cryptophoto_settings_text', 'cryptophoto_settings');
      add_settings_field('cryptophoto_publickey', 'Public Key:', 'cryptophoto_settings_publickey', 'cryptophoto_settings', 'cryptophoto_settings');
      add_settings_field('cryptophoto_privatekey', 'Private Key:', 'cryptophoto_settings_privatekey', 'cryptophoto_settings', 'cryptophoto_settings');
      add_settings_field('cryptophoto_salt', 'Salt:', 'cryptophoto_settings_salt', 'cryptophoto_settings', 'cryptophoto_settings');
      add_settings_field('cryptophoto_server', 'Server:', 'cryptophoto_settings_server', 'cryptophoto_settings', 'cryptophoto_settings');
      add_settings_field('cryptophoto_roles', 'Enable for roles:', 'cryptophoto_settings_roles', 'cryptophoto_settings', 'cryptophoto_settings');
      register_setting('cryptophoto_settings', 'cryptophoto_publickey', 'cryptophoto_publickey_validate');
      register_setting('cryptophoto_settings', 'cryptophoto_privatekey', 'cryptophoto_privatekey_validate');
      register_setting('cryptophoto_settings', 'cryptophoto_salt', 'cryptophoto_salt_validate');
      register_setting('cryptophoto_settings', 'cryptophoto_server', 'cryptophoto_server_validate');
      register_setting('cryptophoto_settings', 'cryptophoto_roles', 'cryptophoto_roles_validate');
  }

  // adds the roles options and register the tabbed view actions
  function cryptophoto_add_page() {
    global $cp_users_list_page;
    $cp_users_list_screen_options = add_options_page('CryptoPhoto', 'CryptoPhoto', 'manage_options', 'cryptophoto_wordpress', 'cryptophoto_configuration_page');

    if(isset($_REQUEST['tab']) && strtolower($_REQUEST['tab']) == "users") {
      add_action("load-$cp_users_list_screen_options", "cp_users_list_screen_options");
    }

    global $wp_roles;
    $roles = $wp_roles->get_names();
    $newroles = array();

    foreach($roles as $key=>$role) {
        $newroles[before_last_bar($key)] = before_last_bar($role);
    }

    $selected = get_option('cryptophoto_roles', $newroles);
    $menu_position = '6.' . time();

    if ( in_array("Administrator", $selected) && current_user_can( "administrator" ) ) {
      add_menu_page('CryptoPhoto', 'CryptoPhoto', 'administrator', 'cryptophoto_user', 'cryptophoto_settings_page', plugins_url('cryptophoto-two-and-multi-factor-authentication/images/icon.png'), $menu_position); 
    } else if ( in_array("Editor", $selected) && current_user_can( "editor" ) ) {
        add_menu_page('CryptoPhoto', 'CryptoPhoto', 'editor', 'cryptophoto_user', 'cryptophoto_settings_page', plugins_url('cryptophoto-two-and-multi-factor-authentication/images/icon.png'), $menu_position); 
    } else if ( in_array("Author", $selected) && current_user_can( "author" ) ) {
        add_menu_page('CryptoPhoto', 'CryptoPhoto', 'author', 'cryptophoto_user', 'cryptophoto_settings_page', plugins_url('cryptophoto-two-and-multi-factor-authentication/images/icon.png'), $menu_position); 
    } else if ( in_array("Contributor", $selected) && current_user_can( "contributor" ) ) {
        add_menu_page('CryptoPhoto', 'CryptoPhoto', 'contributor', 'cryptophoto_user', 'cryptophoto_settings_page', plugins_url('cryptophoto-two-and-multi-factor-authentication/images/icon.png'), $menu_position); 
    } else if ( in_array("Subscriber", $selected) && current_user_can( "subscriber" ) ) {
        add_menu_page('CryptoPhoto', 'CryptoPhoto', 'subscriber', 'cryptophoto_user', 'cryptophoto_settings_page', plugins_url('cryptophoto-two-and-multi-factor-authentication/images/icon.png'), $menu_position); 
    }
  }
    

  // attach the settings link to the Cryptophoto plugin
  function cryptophoto_add_link($links, $file) {
    static $this_plugin;
    if (!$this_plugin) $this_plugin = plugin_basename(__FILE__);
    if ($file == $this_plugin) {
      $settings_link = '<a href="'.get_admin_url(null, 'options-general.php?page=cryptophoto_wordpress').'">'.__("Settings", "cryptophoto_wordpress").'</a>';
      array_unshift($links, $settings_link);
    }
    return $links;
  }


  // addes the screen options for desired columns in the users table, number of users per page\
  function cp_users_list_screen_options() {

    global $usersListTable;

    if(isset($_POST['s']) && $_POST['s'] != "") {
      $filter = 'WHERE user_nicename LIKE "%' . $_POST['s'] . '%" OR user_login LIKE "%' . $_POST['s'] . '%" OR user_email LIKE "%' . $_POST['s'] . '%"';
    }
    else {
      $filter = "";
    }

    $option = 'per_page';
    $args = array(
           'label' => 'Users',
           'default' => 10,
           'option' => 'users_per_page'
           );
    add_screen_option( $option, $args );

    // get the users table, instantiate new CP_Users_List_Table class
    $usersListTable = new CP_Users_List_Table(null, null, $filter);
  }


  // hook for screen options 
  function cp_users_list_set_screen_option($status, $option, $value) {
    if ( 'users_per_page' == $option ) return $value;
  }


  // The Cryptophoto users table page
  function cp_users_list_page() {

    global $usersListTable;
    
    $cp_images = plugins_url('cryptophoto-two-and-multi-factor-authentication/images');
    $image = "";
    $title = "";
  
    // get the current user ID
    $user = get_current_user_id();
    // get the current admin screen
    $screen = get_current_screen();
    // retrieve the "per_page" option
    $screen_option = $screen->get_option('per_page', 'option');
    // retrieve the value of the option stored for the current user
    $per_page = get_user_meta($user, $screen_option, true);

    if ( empty ( $per_page) || $per_page < 1 ) {
      // get the default value if none is set
      $per_page = $screen->get_option( 'per_page', 'default' );
    }

    // a valid action was posted
    if((isset($_POST['action']) && $_POST['action'] != -1) || (isset($_POST['action2']) && $_POST['action2'] != -1)) {
      if($_POST['action'] == 'disable' || $_POST['action'] == 'enable' || $_POST['action2'] == 'disable' || $_POST['action2'] == 'enable') {
        // there were selected users
        if(isset($_POST['user'])) {
          $multiusers = $_POST['user'];  // array of users, for bulk actions
          $i = 0;

          // switch the status for each of the selected users, where necessary
          foreach ($multiusers as $key) {
            $cp_status = get_user_option("cryptophoto_enabled", intval($multiusers[$i]));

            if($_POST['action'] == 'disable' || $_POST['action2'] == 'disable') {
              if($cp_status == 1) {
                update_user_option ( intval($multiusers[$i]), "cryptophoto_enabled", 0);
              }
            }

            if($_POST['action'] == 'enable' || $_POST['action2'] == 'enable') {
              if($cp_status == 0) {
                update_user_option ( intval($multiusers[$i]), "cryptophoto_enabled", 1);
              }
            }    

            $i++;
          }
        }
        else {
          echo "<p><font color='red'> No users were selected! </font></p>";
        }
      }
      else {
        echo "<p><font color='red'> A valid action must be selected! </font></p>";
      }
    }

    // toggle the user's CryptoPhoto status
    if (isset($_POST['userid'])) {
      $cp_status = get_user_option("cryptophoto_enabled", intval($_POST['userid']));
      $cp_status? update_user_option ( $_POST['userid'], "cryptophoto_enabled", 0) : update_user_option ( $_POST['userid'], "cryptophoto_enabled", 1);
      $_REQUEST["Enable"] = 1;
    }
    else {
      $_REQUEST["Enable"] = 0;
    }

/* the form with the user CryptoPhoto status - each user has a 
   corresponding button on the CryptoPhoto status column for switching his CP status */
?>
<form action="admin.php?page=cp_users_list" method="post" name="adminForm">

<?php
    $usersListTable->prepare_items($per_page);

    // add the CryptoPhoto status column to the table
    foreach ($usersListTable->res as $key => $row) {
      if(isset($row['id'])) {
        // get the current user's CryptoPhoto status
        $cp_status = get_user_option("cryptophoto_enabled", intval($row['id']));
        
        // set the CryptoPhoto status image and the tooltip
        // when enabld
        if($cp_status == 1) {
          $image = $cp_images . '/icon.png';
          $title = "Disable CryptoPhoto";
        }
        // when disabled
        else {
          $image = $cp_images . '/icon-grey.png';
          $title = "Enable CryptoPhoto";
        }
      }

      // add the cryptophoto key to the users array
      $usersListTable->res[$key]['cryptophoto'] = '<a align="left" href="#" title="' . $title . '" ' .  
                                                  'onclick="return switchStatus(this, ' . $row['id'] . ')">' .
                                                  '<img style="position:relative;top:5px;" src="' . $image . '">'.
                                                  '</a>';
    }

    $usersListTable->update_items();
?>
  </form>

<?php

    // check for the posted search word
    if(isset($_POST['s']) && $_POST['s'] != '') {
      echo '<span class="subtitle">Search results for "' . $_POST['s'] . '"</span></h2>';
    }
    else {
      echo '</h2>';
    }

    // search/filter form
 ?>
    <form method="post">
      <input type="hidden" name="page" value="cp_users_list_table">
      <?php
      $usersListTable->search_box( 'search', 'search_id' );
      $usersListTable->display(); 
    echo '</form></div>';
?>

<script type="text/javascript">

//Browser Support Code
function switchStatus(el, userid){
  var ajaxRequest;  // The variable that makes Ajax possible!

  try{
    // Opera 8.0+, Firefox, Safari
    ajaxRequest = new XMLHttpRequest();
  } catch (e){
    // Internet Explorer Browsers
    try{
      ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");
    } catch (e) {
      try{
        ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");
      } catch (e) {
        // Something went wrong
        return false;
      }
    }
  }

  // Create a function that will receive data sent from the server
  ajaxRequest.onreadystatechange = function(){
    if(ajaxRequest.readyState == 4 && ajaxRequest.status == 200){

      var res = eval('(' + ajaxRequest.responseText + ')');

      if (res && res.success) {
        el.children[0].setAttribute("src", res.image);
        el.children[0].setAttribute("title", res.title);
      }

    }
  }

  var data = "action=cryptophoto_switch&userid=" + userid;
  ajaxRequest.open("POST", ajaxurl, true);
  ajaxRequest.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
  ajaxRequest.send(data);
  return false;
}

</script>

<?php
  }


  // Process a change in a user's CryptoPhoto status
  function cryptophoto_process_switch() {

    $cp_images = plugins_url('cryptophoto-two-and-multi-factor-authentication/images');
    $image = "";
    $image = $cp_images . '/icon-grey.png';
    $title = "Enable Cryptophoto";
    $enabled = 0;

    // user ID is set
    if (isset($_POST['userid'])) {
      $cp_status = get_user_option("cryptophoto_enabled", intval($_POST['userid']));
      // CryptoPhoto is currently enabled
      if ($cp_status) {
        // disable CryptoPhoto
        update_user_option ( $_POST['userid'], "cryptophoto_enabled", 0);
        $enabled = 0;
      } 
      // CryptoPhoto is currently disabled
      else {
        // enable CryptoPhoto
        update_user_option ( $_POST['userid'], "cryptophoto_enabled", 1);
        $enabled = 1;
      }
    } 
    else {
      echo '{"error":"missing_userid"}';
    }

    // set the tooltip and image for enabled CryptoPhoto
    if($enabled == 1) {
      $image = $cp_images . '/icon.png';
      $title = "Disable Cryptophoto";
    }

    // set the tooltip and image for disabled CryptoPhoto
    else {
      $image = $cp_images . '/icon-grey.png';
      $title = "Enable Cryptophoto";
    }

    echo '{"success":true, "image":"'.$image.'", "title":"'.$title.'"}';
    die();
  }


  // attach the 'Users' link to the CryptoPhoto plugin
  function cryptophotousers_add_link($links, $file) {
    static $this_plugin;
    if (!$this_plugin) $this_plugin = plugin_basename(__FILE__);
    if ($file == $this_plugin) {
      $users_link = '<a href="'.get_admin_url(null, 'options-general.php?page=cryptophoto_wordpress&tab=users').'">'.__("Users", "cryptophotousers_wordpress").'</a>';
      array_unshift($links, $users_link);
    }
    return $links;
  }
    

  // The CryptoPhoto settings page
  function cryptophoto_settings_page() {

    global $current_user;
    $privatekey = get_option('cryptophoto_privatekey');
    $publickey   = get_option('cryptophoto_publickey');
    $salt = get_option('cryptophoto_salt'); 
    $server = get_option('cryptophoto_server');       

    // check for valid CryptoPhoto configuration
    if (!$privatekey or !$publickey or !$salt) {
     echo '<p class="submit"> The plugin is not properly configured. ';
     if (current_user_can( "administrator" )) {
       echo 'You can configure it <a href="'.get_admin_url(null, 'options-general.php?page=cryptophoto_wordpress').'">here</a>.';
     } else {
       echo 'Contact your administrator.';
     }
     echo '</p>';
     return;
    }
           
    $userid = $current_user->ID;
    $isactive = get_user_option("cryptophoto_enabled", $userid);

    // toggle CryptoPhoto
    if (isset($_POST['sb'])) {
      if($isactive) {
        update_user_option ( $userid, "cryptophoto_enabled", 0);
        $isactive = false;
      } 
      else {
        update_user_option ( $userid, "cryptophoto_enabled", 1);
        $isactive = true;
      }
    }

?>
    <form method="post">
      <p class="submit">
        Your CryptoPhoto Authentication service is <?php echo $isactive ? "active ":"inactive "?><input type="submit" name="sb" value="<?php echo $isactive ? "Deactivate":"Activate" ?>" />
      </p>
    </form>      
<?php 
     //"
     $cp = new CryptoPhotoUtils($server, $privatekey,  $publickey, md5($salt . $userid));
     $rv = $cp->start_session($_SERVER['REMOTE_ADDR']);
     
     if (!$rv[0]) {
       echo "Failed to communicate with <strong>cryptophoto.com</strong>. Contact your administrator.";
       return;
     }
       
     $cp_images = plugins_url('cryptophoto-two-and-multi-factor-authentication/images');
?>
<div style="position: absolute; width: 100%; text-align: center;">
  <br/><br/><br/>
  <img id="cp-loader" src="<?php echo $cp_images ?>/loading.gif"></img>
</div>
<?php
    echo $cp->get_gen_widget();
?>
<script type="text/javascript" id="hax">
    var loader = jQuery('#cp-loader');
    loader.fadeOut('slow');
  
    // cleanup
    loader.parent().remove();
    jQuery('#hax').remove();
</script>

<?php
  }


  /*-------------XML-RPC Features-----------------*/


  /*-------------Register WordPress Hooks-------------*/

  add_filter('authenticate', 'cryptophoto_authenticate_user', 10, 3);
  add_filter('plugin_action_links', 'cryptophotousers_add_link', 10, 2);
  add_filter('plugin_action_links', 'cryptophoto_add_link', 10, 2 );
  add_filter('set-screen-option', 'cp_users_list_set_screen_option', 10, 3);
  add_action('admin_menu', 'cryptophoto_add_page');
  add_action('admin_init', 'cryptophoto_admin_init');
  add_action('wp_ajax_cryptophoto_switch', 'cryptophoto_process_switch');
  add_action('wp_ajax_cryptophoto_test', 'cryptophoto_process_test');




?>
