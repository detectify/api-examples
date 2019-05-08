'use strict'

const crypto = require('crypto')
const fetch = require('node-fetch')

// The endpoint to Detectify's API, no trailing slash
const DetectifyEndpoint = 'https://api.detectify.com/rest'

// Generate the headers to use for API calls. If `secretKey` is not null, its value will be used to create
// the signature headers. `body` should be omitted unless the call requires a JSON payload.
function makeHeaders(apiKey, secretKey, method, path, timestamp, body) {
    let headers = {'X-Detectify-Key': apiKey}

    // Add signature headers if secret key is used
    if (secretKey !== null) {
        let signature = signatureHeaders(apiKey, secretKey, method, path, timestamp, body)
        headers = {...headers, ...signature}
    }

    return headers
}

// Generates the signature headers used together with the secret key.
function signatureHeaders(apiKey, secretKey, method, path, timestamp, body) {
    method = method.toUpperCase()

    if (body === null) {
        body = ''
    }

    let data = `${method};${path};${apiKey};${timestamp};${body}`
    let secret = Buffer.from(secretKey, 'base64')

    let hmac = crypto.createHmac('sha256', secret)
    hmac.update(data)
    let signature = hmac.digest('base64')

    return {
        'X-Detectify-Signature': signature,
        'X-Detectify-Timestamp': timestamp,
    }
}

// Starts a scan for the provided scan profile. Returns true if the scan was started, false if not.
function startScan(scanProfile, apiKey, secretKey) {
    const path = `/v2/scans/${scanProfile}/`
    const url = `${DetectifyEndpoint}${path}`
    const timestamp = Math.floor(new Date() / 1000)

    // Create headers for the API call
    const headers = makeHeaders(apiKey, secretKey, 'POST', path, timestamp, null)

    // Perform the call
    fetch(url, {
        method: 'POST',
        headers: headers,
    }).then(function (response) {
        switch (response.status) {
            case 202:
                console.log('Scan start request accepted')
                return true
            case 400:
                console.log('Invalid scan profile token')
                return false
            case 401:
                console.log('Missing/invalid API key or message signature, or invalid timestamp')
                return false
            case 403:
                console.log('The API key cannot access this functionality')
                return false
            case 404:
                console.log('The specified scan profile does not exist or the API cannot access the profile')
                return false
            case 409:
                console.log('A scan is already running on the specified profile')
                return false
            case 423:
                console.log('The domain is not verified')
                return false
            case 500:
            case 503:
                console.log('An error occurred while processing the request')
                return false
            default:
                console.log(`Unhandled API response, got code ${response.status}`)
                return false
        }
    })
}

// Returns the scan status as JSON if the scan is running.
function scanStatus(scanProfile, apiKey, secretKey) {
    const path = `/v2/scans/${scanProfile}/`
    const url = `${DetectifyEndpoint}${path}`
    const timestamp = Math.floor(new Date() / 1000)

    // Create headers for the API call
    const headers = makeHeaders(apiKey, secretKey, 'GET', path, timestamp, null)

    // Perform the call
    fetch(url, {
        method: 'GET',
        headers: headers,
    })
        .then(function (response) {
            switch (response.status) {
                case 200:
                    console.log(response.json())
                    break
                case 400:
                    console.log('Invalid scan profile token')
                    break
                case 401:
                    console.log('Missing/invalid API key or message signature, or invalid timestamp')
                    break
                case 403:
                    console.log('The API key cannot access this functionality')
                    break
                case 404:
                    console.log('No scan running for the specified profile, or the specified scan profile does not exist, or the API cannot access the profile')
                    break
                case 500:
                case 503:
                    console.log('An error occurred while processing the request')
                    break
                default:
                    console.log(`Unhandled API response, got code ${response.status}`)
            }
        })
}

const apiKey = 'd4bf676ee6146557cbf0f28fe6cbc290'
const secretKey = 'SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ=='
const scanProfile = '5605b488634efe810dff4276e28ca7f9'

startScan(scanProfile, apiKey, secretKey)
scanStatus(scanProfile, apiKey, secretKey)
