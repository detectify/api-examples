<?php

// This example uses the Httpful library to make requests. http://phphttpclient.com/
include('httpful.phar');

class Detectify
{
    // Detectify API endpoint, no trailing slash
    private const ENDPOINT = "https://api.detectify.com/rest";

    private $api_key;
    private $secret_key;

    function __construct($api_key, $secret_key)
    {
        $this->api_key = $api_key;
        $this->secret_key = $secret_key;
    }

    function makeHeaders($method, $path, $timestamp, $body = null)
    {
        $method = strtoupper($method);

        if ($body != null) {
            $body = '';
        }

        $msg = "$method;$path;$this->api_key;$timestamp;$body";

        $key = base64_decode($this->secret_key);

        $signature_bytes = hash_hmac('sha256', $msg, $key, true);
        $signature = base64_encode($signature_bytes);

        $headers = array(
            "X-Detectify-Key" => $this->api_key,
            "X-Detectify-Signature" => $signature,
            "X-Detectify-Timestamp" => $timestamp
        );

        return $headers;
    }

    /**
     * Start a scan
     * @param string $scan_profile scan profile to start a scan on
     * @return bool true if a scan was started, false if not
     */
    function startScan($scan_profile)
    {
        $path = "/v2/scans/$scan_profile/";
        $url = self::ENDPOINT . $path;
        $timestamp = time();

        $headers = $this->makeHeaders("POST", $path, $timestamp);

        $response = \Httpful\Request::post($url)
            ->addHeaders($headers)
            ->send();

        switch ($response->code) {
            case 202:
                print("Scan start request accepted");
                return true;
            case 400:
                print("Invalid scan profile token");
                return false;
            case 401:
                print("Missing/invalid API key or message signature, or invalid timestamp");
                return false;
            case 403:
                print("The API key cannot access this functionality");
                return false;
            case 404:
                print("The specified scan profile does not exist or the API cannot access the profile");
                return false;
            case 409:
                print("A scan is already running on the specified profile");
                return false;
            case 423:
                print("The domain is not verified");
                return false;
            case 500:
            case 503:
                print("An error occurred while processing the request");
                return false;
        }
        return false;
    }

    /**
     * Get scan status
     * @param string $scan_profile scan profile to get the scan status for
     */
    function scanStatus($scan_profile)
    {
        $path = "/v2/scans/$scan_profile/";
        $url = self::ENDPOINT . $path;
        $timestamp = time();

        $headers = $this->makeHeaders("GET", $path, $timestamp);

        $response = \Httpful\Request::get($url)
            ->addHeaders($headers)
            ->send();

        switch ($response->code) {
            case 200:
                print_r($response->body);
                break;
            case 400:
                print("Invalid scan profile token");
                break;
            case 401:
                print("Missing/invalid API key or message signature, or invalid timestamp");
                break;
            case 403:
                print("The API key cannot access this functionality");
                break;
            case 404:
                print("The specified scan profile does not exist or the API cannot access the profile");
                break;
            case 500:
            case 503:
                print("An error occurred while processing the request");
        }
    }

}

$api_key = "d4bf676ee6146557cbf0f28fe6cbc290";
$secret_key = "SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ==";
$scan_profile = "5605b488634efe810dff4276e28ca7f9";

$dtfy = new Detectify($api_key, $secret_key);
$dtfy->startScan($scan_profile);
$dtfy->scanStatus($scan_profile);
