package com.detectify;

public class Main {

    public static void main(String[] args) {
        // Detectify keys
        String apiKey = "d4bf676ee6146557cbf0f28fe6cbc290";
        String secretKey = "SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ==";

        // Scan profile token
        String scanProfile = "5605b488634efe810dff4276e28ca7f9";

        // Create new Detectify API client
        Detectify dtfy = new Detectify(apiKey, secretKey);

        // Start a scan and print the current scan status
        dtfy.StartScan(scanProfile);
        dtfy.ScanStatus(scanProfile);
    }
}
