package com.detectify;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Detectify {
    /**
     * Detectify API endpoint, no trailing slash
     */
    private static final String Endpoint = "https://api.detectify.com/rest/v2";

    private String apiKey;
    private String secretKey;

    Detectify(String apiKey, String secretKey) {
        this.apiKey = apiKey;
        this.secretKey = secretKey;
    }

    /**
     * Create the HTTP headers for API requests.
     *
     * @param method    The HTTP method to use for the request, in uppercase
     * @param path      The path of the request
     * @param timestamp The timestamp of the request
     * @param body      The optional body of the request
     */
    private Map<String, String> MakeHeaders(String method, String path, Date timestamp, String body) {
        // Signature timestamp uses Unix epoch time
        Long epoch = timestamp.getTime() / 1000;

        // Format hash payload
        String message = String.format("%s;%s;%s;%s;%s", method, path, this.apiKey, epoch, body);

        // Decode base64 secret key to binary
        byte[] key = Base64.getDecoder().decode(this.secretKey);

        // Create the signature
        String signature = "";
        try {
            Mac hasher = Mac.getInstance("HmacSHA256");
            hasher.init(new SecretKeySpec(key, "HmacSHA256"));

            byte[] hash = hasher.doFinal(message.getBytes());

            // Encode signature back to base64
            signature = Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidKeyException e) {
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Detectify-Key", this.apiKey);
        headers.put("X-Detectify-Signature", signature);
        headers.put("X-Detectify-Timestamp", epoch.toString());

        return headers;
    }

    public boolean StartScan(String scanProfile) {
        Date timestamp = new Date();

        // Format API request URL
        String path = String.format("/scans/%s/", scanProfile);
        String method = "POST";

        URL url;
        try {
            url = new URL(String.format("%s%s", Detectify.Endpoint, path));
        } catch (IOException e) {
        }

        // Create Detectify signature HTTP headers
        Map<String, String> headers = MakeHeaders(method, path, timestamp, "");

        int statusCode;

        // Call the Detectify API
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);

            // Add HTTP headers to request
            for (Map.Entry<String, String> header : headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }

            // Get result of request
            statusCode = conn.getResponseCode();

        } catch (IOException e) {
        }

        switch (statusCode) {
            case 202:
                System.out.println("Scan start request accepted");
                return true;
            case 400:
                System.out.println("Invalid scan profile token");
                return false;
            case 401:
                System.out.println("Missing/invalid API key or message signature, or invalid timestamp");
                return false;
            case 403:
                System.out.println("The API key cannot access this functionality");
                return false;
            case 409:
                System.out.println("A scan is already running on the specified profile");
                return false;
            case 423:
                System.out.println("The domain is not verified");
                return false;
            case 500:
                System.out.println("An error occurred while processing the request");
                return false;
            case 503:
                System.out.println("An error occurred while processing the request");
                return false;
            default:
                System.out.println(String.format("Unhandled API response code: %d", statusCode));
                return false;
        }
    }

    public void ScanStatus(String scanProfile) {
        Date timestamp = new Date();

        // Format API request URL
        String path = String.format("/scans/%s/", scanProfile);
        String method = "GET";

        URL url;
        try {
            url = new URL(String.format("%s%s", Detectify.Endpoint, path));
        } catch (IOException e) {
        }

        // Create Detectify signature HTTP headers
        Map<String, String> headers = MakeHeaders(method, path, timestamp, "");

        int statusCode;

        // Buffer for JSON response
        StringBuffer response = new StringBuffer();

        // Call the Detectify API
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);

            for (Map.Entry<String, String> header : headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }

            // Get result of request
            statusCode = conn.getResponseCode();

            // Read JSON response
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            String inputLine;

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            conn.disconnect();
        } catch (IOException e) {
        }

        switch (statusCode) {
            case 200:
                System.out.println(response);
                break;
            case 400:
                System.out.println("Invalid scan profile token");
                break;
            case 401:
                System.out.println("Missing/invalid API key or message signature, or invalid timestamp");
                break;
            case 403:
                System.out.println("The API key cannot access this functionality");
                break;
            case 404:
                System.out.println("No scan running for the specified profile, or the specified scan profile does not exist or the API key cannot access the scan profile");
            case 500:
                System.out.println("An error occurred while processing the request");
                break;
            case 503:
                System.out.println("An error occurred while processing the request");
                break;
            default:
                System.out.println(String.format("Unhandled API response code: %d", statusCode));
        }
    }

}
