import * as fs from 'fs'
import * as tls from 'tls'
import * as https from 'https'
import {debug, warning} from '@actions/core'
import * as inputs from './inputs'
import * as httpsProxyAgent from 'https-proxy-agent'

export interface SSLConfig {
  trustAllCerts: boolean
  customCA?: string
  combinedCAs?: string[]
}

/**
 * Parse string to boolean
 */
function parseToBoolean(value: string | boolean): boolean {
  if (value !== null && value !== '' && (value.toString().toLowerCase() === 'true' || value === true)) {
    return true
  }
  return false
}

/**
 * Reads and validates SSL configuration from inputs
 */
export function getSSLConfig(): SSLConfig {
  const trustAllCerts = parseToBoolean(inputs.NETWORK_SSL_TRUST_ALL)
  let customCA: string | undefined

  if (trustAllCerts) {
    debug('SSL certificate verification disabled (NETWORK_SSL_TRUST_ALL=true)')
    return {trustAllCerts: true}
  }

  if (inputs.NETWORK_SSL_CERT_FILE) {
    try {
      customCA = fs.readFileSync(inputs.NETWORK_SSL_CERT_FILE, 'utf8')
      debug('Custom CA certificate loaded successfully')

      // Get system CAs and append custom CA
      const systemCAs = tls.rootCertificates || []
      const combinedCAs = [customCA, ...systemCAs]
      debug(`Using custom CA certificate with ${systemCAs.length} system CAs for SSL verification`)

      return {
        trustAllCerts: false,
        customCA,
        combinedCAs
      }
    } catch (error) {
      warning(`Failed to read custom CA certificate file: ${error}`)
    }
  }

  return {trustAllCerts: false}
}

/**
 * Creates an HTTPS agent with combined SSL configuration
 */
export function createHTTPSAgent(sslConfig: SSLConfig): https.Agent {
  const proxyConfig = getProxyConfig()
  const sslOptions: https.AgentOptions = {}

  if (sslConfig.trustAllCerts) {
    debug('Creating HTTPS agent with SSL verification disabled')
    sslOptions.rejectUnauthorized = false
  }

  if (sslConfig.combinedCAs) {
    debug('Creating HTTPS agent with combined CA certificates')
    sslOptions.ca = sslConfig.combinedCAs
    sslOptions.rejectUnauthorized = true
  }

  if (proxyConfig.useProxy && proxyConfig.proxyUrl) {
    debug(`Creating HTTPS proxy agent with proxy: ${proxyConfig.proxyUrl.origin}`)
    return new httpsProxyAgent.HttpsProxyAgent(proxyConfig.proxyUrl, sslOptions)
  }
  if (sslConfig) {
    debug('Creating HTTPS agent without proxy')
    return new https.Agent(sslOptions)
  }
  debug('Creating default HTTPS agent')
  return new https.Agent()
}

/**
 * Creates HTTPS request options with SSL configuration
 */
export function createHTTPSRequestOptions(parsedUrl: URL, sslConfig: SSLConfig, headers?: Record<string, string>): https.RequestOptions {
  const requestOptions: https.RequestOptions = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || 443,
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'GET',
    headers: {
      'User-Agent': 'BlackDuckSecurityAction',
      ...headers
    }
  }

  // Configure SSL options based on settings
  if (sslConfig.trustAllCerts) {
    requestOptions.rejectUnauthorized = false
    debug('SSL certificate verification disabled for this request')
  } else if (sslConfig.combinedCAs) {
    requestOptions.ca = sslConfig.combinedCAs
    debug(`Using combined CA certificates for SSL verification`)
  }

  return requestOptions
}

/**
 * Gets the current SSL configuration as a hash to detect changes
 */
export function getSSLConfigHash(): string {
  const trustAll = parseToBoolean(inputs.NETWORK_SSL_TRUST_ALL)
  const certFile = inputs.NETWORK_SSL_CERT_FILE?.trim() || ''
  return `trustAll:${trustAll}|certFile:${certFile}`
}

function getProxyConfig(): {proxyUrl?: URL; useProxy: boolean} {
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy
  const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy

  const proxyUrl = httpsProxy || httpProxy
  if (!proxyUrl) return {useProxy: false}

  try {
    return {proxyUrl: new URL(proxyUrl), useProxy: true}
  } catch {
    return {useProxy: false}
  }
}
