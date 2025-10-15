import {debug} from '@actions/core'

export interface ProxyConfig {
  useProxy: boolean
  proxyUrl?: URL
}

/**
 * Gets Proxy configuration from environment variables.
 * Supports HTTPS_PROXY/https_proxy and HTTP_PROXY/http_proxy.
 * Respects NO_PROXY/no_proxy which takes priority to bypass proxy for specific hosts.
 * Returns proxy configuration object.
 */
export function getProxyConfig(targetUrl: string): ProxyConfig {
  // Check NO_PROXY first - it takes priority
  const noProxy = process.env.NO_PROXY || process.env.no_proxy
  if (noProxy && shouldBypassProxy(targetUrl, noProxy)) {
    debug(`Bypassing proxy for ${targetUrl} due to NO_PROXY configuration`)
    return {useProxy: false}
  }

  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy
  const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy

  const proxyUrl = httpsProxy || httpProxy
  if (!proxyUrl) {
    return {useProxy: false}
  }

  try {
    return {
      useProxy: true,
      proxyUrl: new URL(proxyUrl)
    }
  } catch {
    return {useProxy: false}
  }
}

/**
 * Determines if a target URL should bypass proxy based on NO_PROXY rules
 */
export function shouldBypassProxy(targetUrl: string, noProxy: string): boolean {
  try {
    const target = new URL(targetUrl)
    const hostname = target.hostname.toLowerCase()

    // Split NO_PROXY by comma and trim whitespace
    const noProxyList = noProxy.split(',').map(entry => entry.trim().toLowerCase())

    for (const entry of noProxyList) {
      if (!entry) continue

      // Handle wildcard patterns (*.example.com)
      if (entry.startsWith('*.')) {
        const domain = entry.substring(2)
        if (hostname === domain || hostname.endsWith(`.${domain}`)) {
          return true
        }
      }
      // Handle wildcard at start (*example.com)
      else if (entry.startsWith('*')) {
        const suffix = entry.substring(1)
        if (hostname.endsWith(suffix)) {
          return true
        }
      }
      // Handle domain suffix match (.example.com matches subdomain.example.com)
      else if (entry.startsWith('.') && hostname.endsWith(entry)) {
        return true
      }
      // Handle exact match or subdomain match
      else if (hostname === entry || hostname.endsWith(`.${entry}`)) {
        return true
      }
    }

    return false
  } catch {
    return false
  }
}
