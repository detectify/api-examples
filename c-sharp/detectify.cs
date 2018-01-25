using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DetectifyExample
{
    internal class Program
    {
        public static async Task Main(string[] args)
        {
            // Detectify keys
            var apiKey = "d4bf676ee6146557cbf0f28fe6cbc290";
            var secretKey = "SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ==";

            // Token for the scan profile
            var scanProfile = "5605b488634efe810dff4276e28ca7f9";

            // Create the API client
            var detectify = new Detectify(apiKey, secretKey);

            // Start a scan
            bool started = await detectify.StartScanAsync(scanProfile);
            if (started)
            {
                // Show scan status if scan successfully started
                await detectify.ScanStatusAsync(scanProfile);
            }
        }
    }

    public class Detectify
    {
        /// <summary>
        /// Detectify API endpoint, without a trailing slash.
        /// </summary>
        private const string Endpoint = "https://api.detectify.com/rest/v2";

        private string ApiKey { get; }
        private string SecretKey { get; }

        public Detectify(string apiKey, string secretKey)
        {
            ApiKey = apiKey;
            SecretKey = secretKey;
        }


        /// <summary>
        /// Create the headers used to sign an API request.
        /// </summary>
        /// <param name="method">The method used for the call, in uppercase.</param>
        /// <param name="path">The path of the request, ie `/v2/domains/`.</param>
        /// <param name="timestamp">The timestamp used when creating the signature.</param>
        /// <param name="body">The body used for requests that require a provided payload. Must be null or an empty string if the request has no body.</param>
        /// <returns>Returns a dictionary of signature headers to use with an API call.</returns>
        private Dictionary<string, string> MakeHeaders(string method, string path,
            DateTime timestamp, string body)
        {
            // Signature timestamp is in Unix epoch format
            var epoch = (long) (timestamp - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds;

            // Calculate signature hash
            var signatureValue = $"{method};{path};{ApiKey};{epoch};{body}";
            var signatureBytes = new HMACSHA256(Convert.FromBase64String(SecretKey))
                .ComputeHash(Encoding.Default.GetBytes(signatureValue));
            var signature = Convert.ToBase64String(signatureBytes);

            return new Dictionary<string, string>
            {
                ["X-Detectify-Key"] = ApiKey,
                ["X-Detectify-Signature"] = signature,
                ["X-Detectify-Timestamp"] = epoch.ToString()
            };
        }

        /// <summary>
        /// Start a scan for a given scan profile.
        /// </summary>
        /// <param name="scanProfile">The scan profile to start a scan on.</param>
        /// <returns>Returns true if a scan was started, false if not.</returns>
        public async Task<bool> StartScanAsync(string scanProfile)
        {
            var path = $"/scans/{scanProfile}/";
            var url = $"{Endpoint}{path}";
            var timestamp = DateTime.UtcNow;

            // Create Detectify headers
            var headers = MakeHeaders("POST", path, timestamp, null);

            using (var client = new HttpClient())
            {
                // Add Detectify headers to request
                headers.ToList().ForEach(h => client.DefaultRequestHeaders.Add(h.Key, h.Value));

                var response = await client.PostAsync(url, null);

                switch ((int) response.StatusCode)
                {
                    case 202:
                        Console.WriteLine("Scan start request accepted");
                        return true;
                    case 400:
                        Console.WriteLine("Invalid scan profile token");
                        return false;
                    case 401:
                        Console.WriteLine("Missing/invalid API key or message signature, or invalid timestamp");
                        return false;
                    case 403:
                        Console.WriteLine("The API key cannot access this functionality");
                        return false;
                    case 404:
                        Console.WriteLine(
                            "The specified scan profile does not exist or the API cannot access the profile");
                        return false;
                    case 409:
                        Console.WriteLine("A scan is already running on the specified profile");
                        return false;
                    case 423:
                        Console.WriteLine("The domain is not verified");
                        return false;
                    case 500:
                    case 503:
                        Console.WriteLine("An error occurred while processing the request");
                        return false;
                    default:
                        Console.WriteLine($"API returned unhandled status code: {(int) response.StatusCode}");
                        return false;
                }
            }
        }

        /// <summary>
        /// Retrieves the status of a currently running scan for a given scan profile.
        /// </summary>
        /// <param name="scanProfile">The scan profile token to check scan status for.</param>
        public async Task ScanStatusAsync(string scanProfile)
        {
            var path = $"/scans/{scanProfile}/";
            var url = $"{Endpoint}{path}";
            var timestamp = DateTime.UtcNow;
            
            // Create Detectify headers
            var headers = MakeHeaders("GET", path, timestamp, null);

            using (var client = new HttpClient())
            {
                // Add Detectify headers to request
                headers.ToList().ForEach(h => client.DefaultRequestHeaders.Add(h.Key, h.Value));

                var response = await client.GetAsync(url);

                switch ((int) response.StatusCode)
                {
                    case 200:
                        Console.WriteLine(await response.Content.ReadAsStringAsync());
                        break;
                    case 400:
                        Console.WriteLine("Invalid scan profile token");
                        break;
                    case 401:
                        Console.WriteLine("Missing/invalid API key or message signature, or invalid timestamp");
                        break;
                    case 403:
                        Console.WriteLine("The API key cannot access this functionality");
                        break;
                    case 404:
                        Console.WriteLine(
                            "No scan running for the specified profile, or the specified scan profile does not exist, or the API cannot access the profile");
                        break;
                    case 500:
                    case 503:
                        Console.WriteLine("An error occurred while processing the request");
                        break;
                    default:
                        Console.WriteLine($"API returned unhandled status code: {(int) response.StatusCode}");
                        break;
                }
            }
        }
    }
}
