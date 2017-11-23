using System.Security.Cryptography;

namespace Test
{
    public class MyHmac
    {
        private string CreateToken(System.Web.HttpRequestBase Request, string Secret)
        {
            var nonce = Request.Headers["X-AUTHY-SIGNATURE-NONCE"];
            var method = Request.HttpMethod;
            var url = Request.Url.AbsoluteUri;
            var form = new string [];
            foreach (string key in Request.Form.Keys)
            {
                form.Add(key + "=" + Request.Form[key]);
            }
            var params = String.join("|", params).Sort();

            var sig = Request.Headers['X-AUTHY-SIGNATURE'];

            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }
    }
}


<?php

function verifyWebhook($apiKey) {
    // Read the nonce from the request
    $nonce = $_SERVER['X-AUTHY-SIGNATURE-NONCE'];
    $method = $_SERVER['REQUEST_METHOD'];

    $proto = isset($_SERVER['HTTPS']) ? "https" : "http";
    $url = "{$proto}://{$_SERVER[HTTP_HOST]}{$_SERVER[REQUEST_URI]}";
    $params = implode('&', array_map(function($k, $v) {
        return "$k=$v";
    }, array_keys($_POST), array_values($_POST)));
    sort($params);

    // concatenate all together and separate them by '|'
    $data = "$nonce|$method|$url|$params";

    // compute the signature
    $computedSig = base64_encode(hash_hmac('sha256', $data, $api_key, true));

    // get the authy signature
    $sig = $_SERVER['X-AUTHY-SIGNATURE'];

    // compare the message signature with your calculated signature
    return hash_equals($computedSig, $sig);
}
