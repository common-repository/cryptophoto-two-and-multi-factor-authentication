=== CryptoPhoto ===
Contributors: 2fa
Donate link: https://cryptophoto.com
Tags: crypto, photo, 2-factor, multi-factor, authentication, token, password, security, login, phishing, keylogger, secure
Requires at least: 3.5
Tested up to: 4.9.4
Stable tag: 1.3
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html


== Description ==

This plugin activates easy self-service two-factor (or multi-factor) authentication logins for you and all your users.

CryptoPhoto is the world's easiest-to-use, fastest, and most secure two-factor (and optionally multi-factor) authentication.  Logins are usually as fast and easy as "one tap", and no training is needed.

After installation, users will see a new "CryptoPhoto" dashboard menu item, which they can use themselves to activate and download printable tokens, or install the CryptoPhoto app to connect their smartphones or tablets (iOS, Android, WindowsPhone, and Blackberry).

Our user-experience testing was conducted using year-1 schoolchildren.  They all successfully logged in without us giving them any instructions. CryptoPhoto is way easier to use, than it is to describe - but here's how it works anyway:

After users activate CryptoPhoto, they will see a photo during their logins, and at the same time, their phone (or tablet) will beep and show them a collection of photos too.  (if they don't have any smart devices, or have lost their phone, they use their downloaded paper token instead).  To complete their login, they simply tap the one on their phone that matches the login one (or type the codes if they don't have a phone, or don't have mobile coverage).  This is why CryptoPhoto is currently the worlds most secure two-factor-authentication - the photos create "mutual authentication" (which blocks phishing and Man-in-the-middle MitM attacks) - nobody else does this.

CryptoPhoto also combats malware, viruses, advanced-persistent-threats (APT's), trojans, keyloggers, phishing and spoof/impostor/fake websites, vishing (telephone phishing), shoulder-surfing attacks, careless password choices by end users, password re-use problems (eg: passwords stolen from other web sites won't compromise CryptoPhoto users), confidence tricks, and more: we simultaneously protect our users against more threats than any competing solution (and, in fact, against more threats than all competing solutions combined).

CryptoPhoto works with or without smartphones/tablets, works home and abroad, online and offline, and keeps working (securely) even when users loose their phones/tablets.  CryptoPhoto is the industries lowest-support-required two-factor-authentication solution: you do not need to hire a support team to mange users enrollments and issues (like bypasses and re-enrollment when users loose their phones/tokens).

To securely install the CryptoPhoto plugin, you will have to follow some steps to generate unique keys for your installation etc.  The steps are on in our [Cryptophoto Installation guide]( https://cryptophoto.com/info/admin ) if you need help, or have comments/suggestions/criticism, please email us or visit [CryptoPhoto Support page]( https://cryptophoto.com/help ), or feel free to call any time on skype:chrisdrake if you want one-to-one help with anything.

For more information, please visit the [CryptoPhoto site]( http://cryptophoto.com )


== Installation ==

AUTOMATIC INSTALLATION 

1. Use the "add new" function which is available in the "Plugins" section of your Wordpress Admin Dashboard
2. Use the search function to find the CryptoPhoto plugin.
3. Install the plugin
4. Activate the plugin


MANUAL INSTALLATION

1. Download "cryptophoto-1.20180612.wordpress.zip" archive from [CryptoPhoto Wordpress plugin page]( https://cryptophoto.com/info/wordpress )
2. Upload* the downloaded file using the regular "Add New" and "Upload" options of your "Plugins" menu

   *To enable file uploads, add the following line to your wp-config.php file:
      define('FS_METHOD', 'direct');

3. Install the extension using the "Install Now" button
4. Activate the plugin through the "Plugins" menu in WordPress
5. Configure the CryptoPhoto plugin:

   1. Click on the "Settings" option of the Cryptophoto Authentication plugin. You can also access this page using the Settings/CryptoPhoto option of the menu
   2. Set the values of the public and private keys to match the API keys you received from CryptoPhoto when you created your administration account
   3. Set the value of your custom salt here (a random or preferred string)
   

TEST YOUR CRYPTOPHOTO INSTALLATION AND CONFIGURATION
   
   1. Use the "Test Configuration" button to verify your configuration.
   2. If successful, your plugin is properly installed and configured
   3. If an error occurs:
      * check the error message and act accordingly
      * check that your plugin is properly installed and that you followed correctly the steps above
      * retry to install and configure the plugin, using the guide here: [CryptoPhoto Wordpress plugin page]( https://cryptophoto.com/info/wordpress )
      * contact [CryptoPhoto Tech Support]( Tech@CryptoPhoto.com )

For more information, please visit [CryptoPhoto Wordpress plugin page]( https://cryptophoto.com/info/wordpress )


== Frequently Asked Questions ==

= 1. What do I do if the Configuration test prompts me the "Error: Unknown error" message? =

You might want to check the Apache error log for more details on the error. If nothing relevant is logged there or you do not have access to the error log, feel free to contact the CryptoPhoto technical support team at [CryptoPhoto Tech Support]( Tech@CryptoPhoto.com ) who can trace and diagnose your error.

= 2. What happens if I change the initial salt  =
This is not a catastrophe. It's not reversible though, all your user's CryptoPhoto settings will be reset, meaning that they will have to re-enable CryptoPhoto authentication for their account and download new tokens. Their previous tokens will be rendered useless and they will have to download new ones.


== Screenshots ==

1. CryptoPhoto Settings page
2. CryptoPhoto Users page
3. CryptoPhoto Panel
4. CryptoPhoto Login


== Changelog ==

= 1.20180612 =
* Improved error handling and reporting

= 1.20180611 =
* CryptoPhoto lib update

= 1.20180307 =
* CryptoPhoto lib update

= 1.20150909 =
* UI Changes
* CryptoPhoto lib update

= 1.20131021 =
* Prevented possible conflicts with other plugins or themes

= 1.20131017 =
* Improved error handling and reporting 
* Corrected a few spelling mistakes and typos

= 1.130812 =
* First CryptoPhoto plugin release


== Upgrade Notice ==

= 1.20180612 =
Improved error handling and reporting

= 1.20180611 =
CryptoPhoto lib update

= 1.20180307 =
CryptoPhoto lib update

= 1.20150909 =
UI Changes. CryptoPhoto lib update

= 1.20131021 =
Randomized the Cryptophoto menu position

= 1.20131017 =
Updated the plugin and library to handle issues related to invald IPs 


= 1.130812 =
This is the initial release of the CryptoPhoto plugin
