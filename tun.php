<?php
/* Copyright (C) 2015, Hsiang Kao (e0e1e) <0xe0e1e@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define('PASS', 'xxxxxx');
define('METHOD', 'AES-256-CFB');
define('BUFSIZ', 3*1024);
define('TV_USEC', 40000);
define('CONNTIMEO_SEC', 4);

// clean the default obs
while (ob_get_level() > 0) ob_end_clean();
ob_start();

header_remove('X-Powered-By');
header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
header('Pragma: no-cache');

// http://www.openssl.org/docs/manmaster/crypto/EVP_BytesToKey.html
function EVP_BytesToKey($pass, $keysiz, $ivsiz)
{
	$Di = '';
	$data = '';
	do {
		$Di = md5($Di . $pass, true);
		$data .= $Di;
	} while(strlen($data) < $keysiz + $ivsiz);
	return array(substr($data, 0, $keysiz), substr($data, $keysiz, $ivsiz));
}

$ivsiz = openssl_cipher_iv_length(METHOD);
$key = EVP_BytesToKey(PASS, 32, 16);
$key = $key[0];

function encrypt($buf)
{
	global $ivsiz, $key;
	$iv = openssl_random_pseudo_bytes($ivsiz);
	$buf = pack("V",strlen($buf)) . $buf;
	return $iv . openssl_encrypt($buf, METHOD, $key, 1, $iv);
}

function decrypt($buf)
{
	global $ivsiz, $key;
	$iv = substr($buf, 0, $ivsiz);
	// ignore size checking
	return substr(openssl_decrypt(substr($buf, $ivsiz), METHOD, $key, 1, $iv), 4);
}

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
	if (!(empty($_GET['e']) || empty($_GET['s']))) {

$rc4_key = EVP_BytesToKey(PASS, 16, 16);
$rc4_key = $rc4_key[0];

function decrypt_rc4_md5_8($buf)
{
	global $rc4_key;
	$iv = substr($buf, 0, 8);
	return openssl_decrypt(substr($buf, 8), 'rc4', md5($rc4_key . $iv, 1), 1);
}

function base64url_decode($base64url)
{
	$base64 = strtr($base64url, '-_', '+/');
	$plainText = base64_decode($base64);
	return ($plainText);
}

		$dst = decrypt_rc4_md5_8(base64url_decode($_GET['e']));
		if (sha1($dst . $_GET['e'] . PASS) == $_GET['s']) {
			$dst = unpack("vp/a*a", $dst . "\0");
			$address = gethostbyname($dst['a']); $port = $dst['p'];
		
			if (empty($_GET['u'])) {		// tcp protocol
				ini_set('max_execution_time', 0);
				ignore_user_abort(true);
				if ($sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) {
					@socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, array('sec' => CONNTIMEO_SEC, 'usec' => 0));
					$res = @socket_connect($sock, $address, $port);
					if ($res) {
						socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, array('sec' => 0, 'usec' => 0));
						
						// make the response header
						if ($_SERVER['SERVER_PROTOCOL'] === 'HTTP/1.0')
							header("Connection: close");
						else
							header("Connection: Keep-Alive");
						
						@session_start();
						header('Content-Type: application/octet-stream');
						
						if (strpos($_SERVER['SERVER_SOFTWARE'], 'nginx') !== false)
							header("X-Accel-Buffering: no");
						
						// dummy hello
						echo encrypt('');
						ob_flush(); flush();

						$_SESSION['writebuf'] = '';
						$closed = $_SESSION['closed'] = false;
						session_write_close();
						
						socket_set_nonblock($sock);
						
						for($_fdr = array($sock), $fdwe = NULL;
							$fdr = $_fdr, socket_select($fdr, $fdwe, $fdwe, 0, TV_USEC) !== false;) {
							
							@session_start();
							if (!empty($_SESSION['writebuf'])) {
								$buf = $_SESSION['writebuf'];
								$_SESSION['writebuf'] = '';
							} else $buf = null;
							$closed = $_SESSION["closed"];
							session_write_close();
							
							if (!empty($buf))
								for($length = strlen($buf);;) {
									$sent = @socket_write($sock, $buf, $length);
									if ($sent === false) {
										$err = socket_last_error($sock);
										if ($err !== 11 && $err !== 140) break 2;
									} else if ($sent < $length) {
										$buf = substr($buf, $sent);
										$length -= $sent;
									} else break;
								}
							
							if (in_array($sock,$fdr)) {
								while(1) {
									$buf = @socket_read($sock, BUFSIZ);
									if ($buf === false) {
										$err = socket_last_error($sock);
										if ($err === 11 || $err === 140) break;
										break 2;
									} else if ($buf === '') break 2;			// end of data
									echo encrypt($buf);
									ob_flush(); flush();
								}
							} else flush();
							
							if ($closed === true ||
								connection_status() != CONNECTION_NORMAL)
								break;
						}
						socket_close($sock);
						ob_flush(); flush();
						
						if (@session_start() === true)
							session_destroy();
						exit;
					}
					socket_close($sock);
				}
			} else {		// udp protocol
			
			}
		}
	} else if (isset($_GET['x'])) {
		@session_start();
		if (@is_string($_SESSION['writebuf'])) {
			$_SESSION["closed"] = true;
			session_write_close();
			exit;
		} else session_write_close();
	}
} else if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$rawPostData = file_get_contents("php://input");
	if ($rawPostData) {
		// decrypt the current data
		$buf = decrypt($rawPostData);

		// client ==> writebuffer
		@session_start();
		if (@is_string($_SESSION['writebuf'])) {
			$_SESSION['writebuf'] .= $buf;
			session_write_close();
			header("Connection: Keep-Alive");
			exit;
		} else session_write_close();
	}
}
header('HTTP/1.1 403 Forbidden');

?>
