<?php

/* DESCRIPTION:
 * This is a PHP library that handles calling CryptoPhoto.
 *    - Main Page
 *        http://cryptophoto.com/
 *    - About Cryptophoto
 *         http://cryptophoto.com/about
 *    - Register to CryptoPhoto
 *        http://cryptophoto.com/register/
 *
 * VERSION: 1.20180307
 * COPYRIGHT(c) 2018 CryptoPhoto -- http://cryptophoto.com/
 * AUTHOR: CryptoPhoto
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


//server
define("SERVER_ERROR", "error-server-not-reachable");
define("REQUEST_ERROR", "error-bad-request");
define("PORT", 80);
define("PORTSSL", 443);

class CryptoPhotoUtils {

  //userdata
  var $server;
  var $privatekey;
  var $publickey;
  var $uid;

  //response properties
  var $is_valid;
  var $sid;
  var $has_token;
  var $error;

  //constructor
  function CryptoPhotoUtils($server, $privatekey="", $publickey="", $uid="") {
    $this->privatekey = $privatekey;
    $this->publickey = $publickey;
    $this->uid = $uid;
    
    if(!empty($server)) {
      $this->server = $server;      
      $this->server = rtrim($this->server, '/');    

      if( ( strcmp(substr($server, 0, 7), "http://") != 0 ) && (strcmp(substr($server, 0, 8), "https://") != 0)) {
        $this->server = "http://" . $server;          
      }
    }
    else {
      $this->server = "https://cryptophoto.com";  
    }
  }


  /**
   * encodes the given data into a query string format
   * @param $data - array of string elements to be encoded
   * @return string - encoded request
   */
  function string_encode ($data) {
    $req = "";
    foreach ($data as $key => $value)
            $req .= $key . '=' . urlencode(stripslashes($value)) . '&';

    //cut the last '&'
    $req = substr($req, 0, strlen($req) - 1);
    return $req;
  }


  /**
  * sends an http post-request to an URL
  * @param string $url
  * @param string $udata
  * @return array response*/
  function post_request($url, $udata) {

    if(function_exists('curl_init')) {

      $req = $this->string_encode($udata);
      $cookies = "";
      $response = "";
      $data = array (
                  'http' => array ( 
                    'method' => 'POST',
                    'header'=> "Content-type: application/x-www-form-urlencoded\r\n"
                    . "Content-Length: " . strlen($req) . "\r\n"
                    . "Cookie: " . $cookies."\r\n",
                    'content' => $req
                  )
                );

      $ch = curl_init ($url);
      curl_setopt ($ch, CURLOPT_CAINFO, dirname(__FILE__) . '/cacert.pem');
      curl_setopt ($ch, CURLOPT_POST, true);
      curl_setopt ($ch, CURLOPT_POSTFIELDS, $req);
      curl_setopt ($ch, CURLOPT_RETURNTRANSFER, true);
      $response = curl_exec($ch);
      if(curl_errno($ch)) { error_log("CURL error: " . curl_error ($ch)); }
    }

    else {
      $req = $this->string_encode ($udata);
      $url = parse_url($url);
      $extra = "";
      $port = PORT;

      if ($url['scheme'] == 'https') {
        $extra = "ssl://";
        $port = PORTSSL;
      }

      //extract the components from the URL
      $host = $extra . $url['host'];
      $path = $url['path'];

      //compose the http request
      $http_request = "POST $path HTTP/1.0\r\n";
      $http_request .= "Host: $host\r\n";
      $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
      $http_request .= "Content-Length: " . strlen($req) . "\r\n";
      $http_request .= "User-Agent: CryptoPhoto/PHP\r\n";
      $http_request .= "\r\n";
      $http_request .= $req;

      //check the response
      $response = '';

      if(false == ($fs = @fsockopen($host, $port, $errno, $errstr, 60))) {
        error_log("Couldn't connect to $host: $errno, $errstr",0);
        return null;
      }

      //write the request on socket
      fwrite($fs, $http_request);

      while (!feof($fs)) {
        //one tcp/ip packet
        $response .= fgets($fs, 1160);
      }

      //close socket
      fclose($fs);
      $response = explode("\r\n\r\n", $response, 2);
    }
    
    return $response;
  }

  /**
  * sends an http get-request to an URL
  * @param string $url
  * @return array response*/
  function get_request($url) {

    if (function_exists('curl_init')) {
      $ch = curl_init ($url);
      curl_setopt ($ch, CURLOPT_CAINFO, dirname(__FILE__) . '/cacert.pem');
      curl_setopt ($ch, CURLOPT_RETURNTRANSFER, true);
      $response = curl_exec($ch);
      if(curl_errno($ch)) { error_log("CURL error: " . curl_error ($ch)); }
    }

    else {
      $url = parse_url($url);
      $extra = "";
      $port = PORT;

      if ($url['scheme'] == 'https') {
        $extra = "ssl://";
        $port = PORTSSL;
      }

      //extract the components from the URL
      $host = $extra . $url['host'];
      $path = $url['path'];

      //compose the http request
      $http_request = "GET $path HTTP/1.0\r\n";
      $http_request .= "Host: $host\r\n";
      $http_request .= "Content-Length: 0\r\n";
      $http_request .= "User-Agent: CryptoPhoto/PHP\r\n";
      $http_request .= "\r\n";

      //check the response
      $response = '';

      if(false == ($fs = @fsockopen($host, $port, $errno, $errstr, 60))) {
        error_log("Couldn't connect to $host: $errno, $errstr",0);
        return null;
      }

      //write the request on socket
      fwrite($fs, $http_request);

      while (!feof($fs)) {
        //one tcp/ip packet
        $response .= fgets($fs, 1160);
      }

      //close socket
      fclose($fs);
    }
    
    return $response;
  }

  /**
  * request a new session
  * @return array */
  function start_session($ip, $authentication = false) {

    $time = time();

    $data['publickey'] = $this->publickey;
    $data['uid'] = $this->uid; 
    $data['time'] = $time;
    $data['signature'] = $this->make_signature($this->uid, $this->publickey, $this->privatekey, $time);
    $data['ip'] = $ip;
    if ($authentication) $data['authentication'] = "true";

    $scheme = parse_url($this->server);
       
    if($scheme['scheme'] == 'https') {
      if(function_exists('curl_init')) {
        $response = $this->post_request($this->server . "/api/get/session", $data);
      }
      else {
        $this->server = str_replace("https://", "http://" , $this->server); 
        $response = $this->post_request($this->server . "/api/get/session", $data);
      }
    }   
    else {
      $response = $this->post_request($this->server . "/api/get/session", $data);
    }   

    if($response != null && $response != '') {
      //successful request
      
      if(function_exists('curl_init')) {
        $answer = explode("\n", $response);
      }
      else {
        $answer = explode("\n", $response[1]);
      }

      if($answer[0] == 'success') {
        $this->is_valid = TRUE;
        $this->sid = $answer[1];
        $this->has_token = $answer[2];
        return array($this->is_valid, $this->sid, $this->has_token);
      }
      else {
        $this->is_valid = FALSE;
        $this->error = $answer[1];
        $errip = "";
        if(isset($answer[3])) {
          $errip = $answer[3];
        }
        return array($this->is_valid, $this->error, $errip);
      }
    }

    //server unreachable or bad request
    else {
      $this->is_valid = FALSE;
      $this->error = SERVER_ERROR;
      return array($this->is_valid, $this->error);
    }
  }


  /**
  * generate javascript code for getting a token
  * @return string */
  function get_gen_widget() {
    if($this->sid != null && $this->sid != '') {
      return '<script type="text/javascript" src="' . $this->server . '/api/token?sd=' . $this->sid . '"></script>';
    } 
    else {
      die ("Generate session first");
    }
  }

  /**
  * generate javascript code for getting a challenge
  * @return string */
  function get_auth_widget() {
    if($this->sid != null && $this->sid != '') {
      return '<script type="text/javascript" src="' . $this->server . '/api/challenge?sd=' . $this->sid . '"></script>';
    } 
    else {
      die ("Generate session first");
    }
  }


  /**
  * post and check a user's response for a given challenge
  * @param string $response_row
  * @param string $response_col
  * @param string $ip
  * @return array */
  function verify_response($selector, $response_row, $response_col, $cp_phc, $ip) {

    if($selector == null || $selector == '') {
      $this->is_valid = FALSE;
      $this->error = SERVER_ERROR;
      //invalid request
      return array("is_valid" => $this->is_valid, "error" => $this->error);
    }
    else {
      if(($response_row == null || $response_row == '' || $response_col == null || $response_col == '') && ($cp_phc == null || $cp_phc == '')) {
        $this->is_valid = FALSE;
        $this->error = SERVER_ERROR;
        //invalid request
        return array("is_valid" => $this->is_valid, "error" => $this->error);
      }
    }

    $time = time(); 
    //compose userdata
    $data['publickey'] = $this->publickey;
    $data['time'] = $time;
    $data['signature'] = $this->make_signature($this->uid, $this->publickey, $this->privatekey, $time);
    $data['uid'] = $this->uid;
    $data['response_row'] = $response_row;
    $data['response_col'] = $response_col;
    $data['selector'] = $selector;
    $data['cph'] = $cp_phc;
    $data['ip'] = $ip;

    $scheme = parse_url($this->server);
       
    if($scheme['scheme'] == 'https') {
      if(function_exists('curl_init')) {
        $response = $this->post_request($this->server . "/api/verify", $data);
      }
      else {
        $this->server = str_replace("https://", "http://", $this->server); 
        $response = $this->post_request($this->server . "/api/verify", $data);
      }
    }   
    else {
      $response = $this->post_request($this->server . "/api/verify", $data);
    }   
    
    if($response != null && $response !='') {

      if(function_exists('curl_init')) {
        $answer = explode("\n", $response);
      }
      else {
        $answer = explode("\n", $response[1]);
      }

      //successful request
      if($answer[0] == 'success') {
        //challenge matching successful
        $this->is_valid = TRUE;
        $this->message = $answer[1];
        return array("is_valid" => $this->is_valid, "message" => $this->message);
      }
      else {
        //challenge matching error
        $this->is_valid = FALSE;
        $this->error = $answer[1];
        return array("is_valid" => $this->is_valid, "error" => $this->error = $answer[1]);
      }
    }
    else {
      $this->is_valid = FALSE;
      $this->error = SERVER_ERROR;
      //server unreachable or bad request
      return array("is_valid" => $this->is_valid, "error" => $this->error);
    }
  }


  /** 
  * creates the user signature  
  * @param string $uid 
  * @param string $publickey 
  * @param string $privatekey 
  * @param string $time 
  * @return string */ 
  function make_signature($uid, $publickey, $privatekey, $time) { 

    if (function_exists("hash_hmac")) { 
      return hash_hmac("sha1", $privatekey . $time . $uid . $publickey, $privatekey, false); 
    } 
    else { 
      return $this->hmac("sha1", $privatekey . $time . $uid . $publickey, $privatekey, false); 
    } 
  } 
   
   
  function hmac($algo, $data, $key, $raw_output = false) { 
    $algo = strtolower($algo); 
    $pack = 'H'.strlen($algo('test')); 
    $size = 64; 
    $opad = str_repeat(chr(0x5C), $size); 
    $ipad = str_repeat(chr(0x36), $size); 
 
    if (strlen($key) > $size) { 
        $key = str_pad(pack($pack, $algo($key)), $size, chr(0x00)); 
    } else { 
        $key = str_pad($key, $size, chr(0x00)); 
    } 
 
    for ($i = 0; $i < strlen($key) - 1; $i++) { 
        $opad[$i] = $opad[$i] ^ $key[$i]; 
        $ipad[$i] = $ipad[$i] ^ $key[$i]; 
    } 
 
    $output = $algo($opad.pack($pack, $algo($ipad.$data))); 
 
    return ($raw_output) ? pack($pack, $output) : $output; 
  } 

  function verify_cptv_response ($parms) {

     if (isset($parms['cpJWSrfc7515'])) {

       $scheme = parse_url($this->server);

       $data['token'] = $parms['cpJWSrfc7515'];

       if ($scheme['scheme'] == 'https') {
         if (function_exists('curl_init')) {
           $response = $this->post_request($this->server . "/api/verify/cptv.json", $data);
         }
         else {
           $this->server = str_replace("https://", "http://", $this->server);
           $response = $this->post_request($this->server . "/api/verify/cptv.json", $data);
         }
       }
       else {
         $response = $this->post_request($this->server . "/api/verify/cptv.json", $data);
       }

       if ($response != null && $response != '') {
         $obj = $this->jsonDecode($response);

         if ($obj != null) {

           if ($this->property_exists($obj, "success") && $obj->success) {

             $jwt = $parms['cpJWSrfc7515'];

             $tks = explode('.', $jwt);

             $payload = $this->jsonDecode($this->urlsafeB64Decode($tks[1]));

             if ($payload != null && $this->property_exists($payload, "fieldsOrder") && $this->property_exists($payload, "fieldsSha256")) {

               $fieldsOrder = $payload->fieldsOrder;
               $fieldsSha256 = $payload->fieldsSha256;

               $fields = explode(",", $fieldsOrder);

               $shacontent="";

               foreach ($fields as $field) {
                 if(isset($parms[$field]) && $parms[$field]) $shacontent .= $parms[$field];
               }

               $shacontent = base64_encode($this->hash256($shacontent));
               $shacontent = str_replace('=', '', $shacontent); // remove the padding bit, they might not match because of it
               $fieldsSha256 = str_replace('=', '', $fieldsSha256);

               if ($fieldsSha256 == $shacontent) {
                 return array("is_valid" => TRUE);
               } else {
                 return array("is_valid" => FALSE, "error" => "POSTed field values have been changed");
               }

             }

           } else {
             return array("is_valid" => FALSE, "error" => $obj->description);
           }
        
         } else {
           return array("is_valid" => FALSE, "error" => "CRYPTOPHOTO responded with invalid format");
         }
         
       } else {
         return array("is_valid" => FALSE, "error" => SERVER_ERROR);
       }
    }  

    return array("is_valid" => FALSE, "error" => "JWT token not provided");

  }

  function property_exists ($obj, $property) {
    if ( !function_exists( 'property_exists' ) ) {
      if ( is_object( $obj ) ) {
        $vars = get_object_vars( $obj );
      } else {
        $vars = get_class_vars( $obj );
      }
      return array_key_exists( $property, $vars );
    }
    return property_exists($obj, $property);
  }

  function hash256($input) {
    if ( !function_exists('hash') ) {
      require_once("sha256.php");
      return SHA256::hash($input, "bin");
    }

    return hash("sha256", $input, True);
  }

  function jsonDecode($input) {

    if ( !function_exists('json_decode') ) {
      require_once("JSON.php");
      $json = new Services_JSON();
      return $json->decode($input);
    }

    if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
      $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
    } else {
      $max_int_length = strlen((string) PHP_INT_MAX) - 1;
      $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
      $obj = json_decode($json_without_bigints);
    }
    if (function_exists('json_last_error') && $errno = json_last_error()) {
      return null;
    } elseif ($obj === null && $input !== 'null') {
      return null;
    }
    return $obj;
  }

  function urlsafeB64Decode($input) {
    $remainder = strlen($input) % 4;
    if ($remainder) {
      $padlen = 4 - $remainder;
      $input .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($input, '-_', '+/'));
  }
    
} 

?>
