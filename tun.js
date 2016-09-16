/* Copyright (C) 2015, Hsiang Kao (e0e1e) <0xe0e1e@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
HIGHWAY_HTTP_UNIX_PATH = "/var/run/shm/highway.sock";
//HIGHWAY_HTTP_PORT = 8080;
HIGHWAY_PASS = "xxxxxx";
HIGHWAY_METHOD = "aes-256-cfb";
HIGHWAY_BUFSIZ = 64*1024;
HIGHWAY_RECVCONN_MIME_TYPE = "application/octet-stream";

var crypto = require("crypto");
var http = require("http");
var url = require("url");
var net = require('net');

HIGHWAY_PASS = new Buffer(HIGHWAY_PASS);

// http://www.openssl.org/docs/manmaster/crypto/EVP_BytesToKey.html
function EVP_BytesToKey(pass, keysiz, ivsiz)
{
//	pass = new Buffer(pass);
	var data = new Buffer(keysiz+ivsiz);
	var Di = new Buffer(0);
	var i = 0;
	do {
		Di = crypto.createHash("md5").update(Di).update(pass).digest();
		Di.copy(data, i);
		i += Di.length;
	} while(i < keysiz + ivsiz);
	return data;
}

const key = EVP_BytesToKey(HIGHWAY_PASS, 32, 0/*16*/);
const ivsiz = 16;

function encrypt(buf)
{
	var iv = crypto.randomBytes(ivsiz);
	var enc = crypto.createCipheriv(HIGHWAY_METHOD, key, iv);
	var lenBuf = new Buffer(4);
	lenBuf.writeUInt32LE(buf.length, 0, true);
	return Buffer.concat([iv, enc.update(Buffer.concat([lenBuf, buf]))]);
}

function decrypt(buf)
{
	var iv = buf.slice(0, ivsiz);
	var dec = crypto.createDecipheriv(HIGHWAY_METHOD, key, iv);
	// ignore size checking
	return dec.update(buf.slice(ivsiz)).slice(4);
}

const rc4_key = EVP_BytesToKey(HIGHWAY_PASS, 16, 0);

function decrypt_rc4_md5_8(buf)
{
	var iv = buf.slice(0, 8);
	var hash = crypto.createHash("md5").update(rc4_key).update(iv);
	
	var dec = crypto.createDecipheriv("rc4", hash.digest(), new Buffer(0));
	return dec.update(buf.slice(8));
}

function getcookies(cookie)
{
	var cookies = {};
	cookie && cookie.split(';').forEach(function(s) {
		var parts = s.split('=');
		cookies[parts[0].trim()] = (parts[1]||'').trim();
	});
	return cookies;
}

var sessions = {};

var server = http.createServer(function(request, response) {
	var headers = request.headers;
	var body = [];
	request.on("error", function (err) {
		console.error("%s, request[error, %s]: %s",
			Date(), headers['x-real-ip'], err);

		response.statusCode = 400;
		response.end();
		// see http://www.bennadel.com/blog/2678-error-events-
		// don-t-inherently-stop-streams-in-node-js.htm
	}).on("data", function (chunk) {
		body.push(chunk);
	}).on("end", function () {
		if (response.finished) return;

		response.on("error", function(err) {
			console.error("%s, response[error, %s]: %s",
				Date(), headers['x-real-ip'], err);
		}).on("close", function() {
			response.end();
		});

		var args = url.parse(request.url, true).query;
		
		response.setHeader("Cache-Control",
			"no-cache, no-store, max-age=0, must-revalidate");
		response.setHeader("Pragma", "no-cache");

		switch(request.method) {
			case "GET":
				if ("e" in args && "s" in args) {
					var dst = new Buffer(args.e.replace('-', '+').replace(
						'_', '/'), 'base64');
					dst = decrypt_rc4_md5_8(dst);
					
					var sha1 = crypto.createHash("sha1");
					sha1.update(dst).update(args.e).update(HIGHWAY_PASS);
					
					if (sha1.digest("hex") == args.s) {

						var port = dst.readInt16LE(0, true);
						var address = dst.toString('ascii', 2);
						
						response.setHeader("Content-Type",
							HIGHWAY_RECVCONN_MIME_TYPE);
						var sid = crypto.randomBytes(16).toString("hex").toUpperCase();

						response.setHeader("Set-Cookie",
							"JSESSIONID=" + sid + ";path=/");

						if (!("u" in args)) {	// tcp protocol

							var socket = net.connect(port,
								address, function() {
								
								// if having been closed before
								// connection is established
								if (response.finished) {
									socket.end();
									return;
								}

								response.on("close", function() {
									// we should delete first bacause
									// close->(end)->sockw->end
									delete sessions[sid];
									socket.end();
									// and this will emit socket 'end' event
								});
								
								socket.on("end", function() {
									delete sessions[sid];
									response.end();
								}).on("error", function(err) {
									delete sessions[sid];
								});
								
								sessions[sid] = {socket : socket,
									port : port, address : address};

								socket.on("data", function(buf) {
									if (response.finished) return;

									isQueued = false;
									while(buf.length > HIGHWAY_BUFSIZ) {
										if (response.write(encrypt(buf.slice(0,
											HIGHWAY_BUFSIZ))) === false)
												isQueued = true;
										buf = buf.slice(HIGHWAY_BUFSIZ);
									}
									if (response.write(encrypt(buf)) === false)
										isQueued = true;
									if (isQueued === true) socket.pause();
								});

								response.on("drain", function() {
									socket.resume();
								});

								// statusCode: 200
								// dummy hello
								response.write(encrypt(new Buffer(0)));
							});

							socket.on("error", function(err) {
								console.error("%s, socket[error, %s=>%s:%d]: %s",
									Date(), headers['x-real-ip'], address, port, err);
								
								// 对方主机没响应
								response.statusCode = 403;
								response.end();

								// https://www.youtube.com/watch?v=PuGmMmNtPmQ
								socket.destroy();
							});
							
							return;
						}
					}
				} else if ("x" in args) {
					var sid = getcookies(headers.cookie)["JSESSIONID"];
					if (sid !== undefined && sid in sessions) {
						sessions[sid].socket.end();
						delete sessions[sid];	// prevent (end)->sockw->end
						response.end();
						return;
					}
				}
				break;
			case "POST":
				var sid = getcookies(headers.cookie)["JSESSIONID"];
				if (sid !== undefined && sid in sessions) {
					sessions[sid].socket.write(decrypt(Buffer.concat(body)));
					response.end();
					return;
				}
		}
		response.statusCode = 403;
		response.end();
	});
});

if(typeof(HIGHWAY_HTTP_PORT)!=='undefined')
	server.listen(HIGHWAY_HTTP_PORT);
else if (typeof(HIGHWAY_HTTP_UNIX_PATH)!=='undefined') {
	var fs = require("fs");
	fs.stat(HIGHWAY_HTTP_UNIX_PATH, function(err) {
		if (!err) fs.unlinkSync(HIGHWAY_HTTP_UNIX_PATH);
		server.listen(HIGHWAY_HTTP_UNIX_PATH);
	});
} else server.error("listening port is not specified");
