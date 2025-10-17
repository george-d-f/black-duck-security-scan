import {describe, test, expect, jest, beforeEach} from '@jest/globals'

describe('Proxy Utils Unit Tests', () => {
  let proxyUtils: any
  let mockCore: any

  beforeEach(() => {
    jest.resetModules()

    mockCore = {
      debug: jest.fn(),
      warning: jest.fn()
    }

    // Mock modules
    jest.doMock('@actions/core', () => mockCore)

    // Import after mocking
    proxyUtils = require('../../../src/blackduck-security-action/proxy-utils')
  })

  describe('getProxyConfig', () => {
    let originalEnv: NodeJS.ProcessEnv

    beforeEach(() => {
      originalEnv = {...process.env}
    })

    afterEach(() => {
      process.env = originalEnv
    })

    test('should return useProxy=false when no proxy environment variables are set', () => {
      delete process.env.HTTPS_PROXY
      delete process.env.https_proxy
      delete process.env.HTTP_PROXY
      delete process.env.http_proxy

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result).toEqual({useProxy: false})
    })

    test('should return proxy config when HTTPS_PROXY is set', () => {
      process.env.HTTPS_PROXY = 'https://proxy.example.com:8080'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('https://proxy.example.com:8080'))
    })

    test('should return proxy config when https_proxy is set', () => {
      process.env.https_proxy = 'http://proxy.example.com:3128'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('http://proxy.example.com:3128'))
    })

    test('should return proxy config when HTTP_PROXY is set', () => {
      process.env.HTTP_PROXY = 'http://proxy.company.com:8080'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('http://proxy.company.com:8080'))
    })

    test('should return proxy config when http_proxy is set', () => {
      process.env.http_proxy = 'http://proxy.localhost:3128'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('http://proxy.localhost:3128'))
    })

    test('should prioritize HTTPS_PROXY over HTTP_PROXY', () => {
      process.env.HTTPS_PROXY = 'https://https-proxy.example.com:8080'
      process.env.HTTP_PROXY = 'http://http-proxy.example.com:3128'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('https://https-proxy.example.com:8080'))
    })

    test('should prioritize https_proxy over http_proxy', () => {
      process.env.https_proxy = 'https://https-proxy.example.com:8080'
      process.env.http_proxy = 'http://http-proxy.example.com:3128'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('https://https-proxy.example.com:8080'))
    })

    test('should prioritize uppercase over lowercase environment variables', () => {
      process.env.HTTPS_PROXY = 'https://uppercase-proxy.example.com:8080'
      process.env.https_proxy = 'https://lowercase-proxy.example.com:8080'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('https://uppercase-proxy.example.com:8080'))
    })

    test('should handle invalid proxy URLs gracefully', () => {
      process.env.HTTPS_PROXY = 'invalid-url'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result).toEqual({useProxy: false})
    })

    test('should handle empty proxy URL', () => {
      process.env.HTTPS_PROXY = ''

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result).toEqual({useProxy: false})
    })

    test('should handle proxy URL with authentication', () => {
      process.env.HTTPS_PROXY = 'http://user:pass@proxy.example.com:8080'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('http://user:pass@proxy.example.com:8080'))
    })

    test('should handle socks proxy URL', () => {
      process.env.HTTPS_PROXY = 'socks5://socks-proxy.example.com:1080'

      const result = proxyUtils.getProxyConfig('https://example.com/api')

      expect(result.useProxy).toBe(true)
      expect(result.proxyUrl).toEqual(new URL('socks5://socks-proxy.example.com:1080'))
    })

    describe('NO_PROXY support', () => {
      beforeEach(() => {
        process.env.HTTPS_PROXY = 'https://proxy.example.com:8080'
      })

      test('should bypass proxy when target matches NO_PROXY exact hostname', () => {
        process.env.NO_PROXY = 'example.com,test.local'

        const result = proxyUtils.getProxyConfig('https://example.com/api')

        expect(result).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/api due to NO_PROXY configuration')
      })

      test('should bypass proxy when target matches no_proxy (lowercase)', () => {
        process.env.no_proxy = 'example.com,test.local'

        const result = proxyUtils.getProxyConfig('https://example.com/api')

        expect(result).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/api due to NO_PROXY configuration')
      })

      test('should bypass proxy for wildcard domain (*.example.com)', () => {
        process.env.NO_PROXY = '*.example.com'

        const result1 = proxyUtils.getProxyConfig('https://api.example.com/test')
        const result2 = proxyUtils.getProxyConfig('https://sub.example.com/path')
        const result3 = proxyUtils.getProxyConfig('https://example.com/root')

        expect(result1).toEqual({useProxy: false})
        expect(result2).toEqual({useProxy: false})
        expect(result3).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://api.example.com/test due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://sub.example.com/path due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/root due to NO_PROXY configuration')
      })

      test('should bypass proxy for domain suffix (.example.com)', () => {
        process.env.NO_PROXY = '.example.com'

        const result1 = proxyUtils.getProxyConfig('https://api.example.com/test')
        const result2 = proxyUtils.getProxyConfig('https://sub.example.com/path')

        expect(result1).toEqual({useProxy: false})
        expect(result2).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://api.example.com/test due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://sub.example.com/path due to NO_PROXY configuration')
      })

      test('should bypass proxy for subdomain match', () => {
        process.env.NO_PROXY = 'example.com'

        const result1 = proxyUtils.getProxyConfig('https://api.example.com/test')
        const result2 = proxyUtils.getProxyConfig('https://example.com/root')

        expect(result1).toEqual({useProxy: false})
        expect(result2).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://api.example.com/test due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/root due to NO_PROXY configuration')
      })

      test('should bypass proxy for wildcard suffix (*example.com)', () => {
        process.env.NO_PROXY = '*example.com'

        const result1 = proxyUtils.getProxyConfig('https://testexample.com/api')
        const result2 = proxyUtils.getProxyConfig('https://sub.example.com/path')

        expect(result1).toEqual({useProxy: false})
        expect(result2).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://testexample.com/api due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://sub.example.com/path due to NO_PROXY configuration')
      })

      test('should use proxy when target does not match NO_PROXY', () => {
        process.env.NO_PROXY = 'example.com,test.local'

        const result = proxyUtils.getProxyConfig('https://other.com/api')

        expect(result.useProxy).toBe(true)
        expect(result.proxyUrl).toEqual(new URL('https://proxy.example.com:8080'))
      })

      test('should handle multiple NO_PROXY entries with whitespace', () => {
        process.env.NO_PROXY = ' example.com , test.local , *.internal.com '

        const result1 = proxyUtils.getProxyConfig('https://example.com/api')
        const result2 = proxyUtils.getProxyConfig('https://test.local/path')
        const result3 = proxyUtils.getProxyConfig('https://api.internal.com/test')

        expect(result1).toEqual({useProxy: false})
        expect(result2).toEqual({useProxy: false})
        expect(result3).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/api due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://test.local/path due to NO_PROXY configuration')
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://api.internal.com/test due to NO_PROXY configuration')
      })

      test('should prioritize NO_PROXY over HTTPS_PROXY', () => {
        process.env.HTTPS_PROXY = 'https://proxy.example.com:8080'
        process.env.NO_PROXY = 'bypass.com'

        const result = proxyUtils.getProxyConfig('https://bypass.com/api')

        expect(result).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://bypass.com/api due to NO_PROXY configuration')
      })

      test('should handle case insensitive matching', () => {
        process.env.NO_PROXY = 'EXAMPLE.COM'

        const result = proxyUtils.getProxyConfig('https://example.com/api')

        expect(result).toEqual({useProxy: false})
        expect(mockCore.debug).toHaveBeenCalledWith('Bypassing proxy for https://example.com/api due to NO_PROXY configuration')
      })

      test('should handle invalid target URL gracefully', () => {
        process.env.NO_PROXY = 'example.com'

        const result = proxyUtils.getProxyConfig('invalid-url')

        expect(result.useProxy).toBe(true)
        expect(result.proxyUrl).toEqual(new URL('https://proxy.example.com:8080'))
      })

      test('should use proxy when NO_PROXY is empty', () => {
        process.env.NO_PROXY = ''

        const result = proxyUtils.getProxyConfig('https://example.com/api')

        expect(result.useProxy).toBe(true)
        expect(result.proxyUrl).toEqual(new URL('https://proxy.example.com:8080'))
      })
    })
  })

  describe('shouldBypassProxy', () => {
    test('should return true for exact hostname match', () => {
      const result = proxyUtils.shouldBypassProxy('https://example.com/api', 'example.com')
      expect(result).toBe(true)
    })

    test('should return true for subdomain match', () => {
      const result = proxyUtils.shouldBypassProxy('https://api.example.com/test', 'example.com')
      expect(result).toBe(true)
    })

    test('should return true for wildcard domain match (*.example.com)', () => {
      const result1 = proxyUtils.shouldBypassProxy('https://api.example.com/test', '*.example.com')
      const result2 = proxyUtils.shouldBypassProxy('https://example.com/root', '*.example.com')
      expect(result1).toBe(true)
      expect(result2).toBe(true)
    })

    test('should return true for domain suffix match (.example.com)', () => {
      const result = proxyUtils.shouldBypassProxy('https://api.example.com/test', '.example.com')
      expect(result).toBe(true)
    })

    test('should return true for wildcard prefix match (*example.com)', () => {
      const result = proxyUtils.shouldBypassProxy('https://testexample.com/api', '*example.com')
      expect(result).toBe(true)
    })

    test('should return false for non-matching domain', () => {
      const result = proxyUtils.shouldBypassProxy('https://other.com/api', 'example.com')
      expect(result).toBe(false)
    })

    test('should handle invalid URLs gracefully', () => {
      const result = proxyUtils.shouldBypassProxy('invalid-url', 'example.com')
      expect(result).toBe(false)
    })

    test('should handle case insensitive matching', () => {
      const result = proxyUtils.shouldBypassProxy('https://EXAMPLE.COM/api', 'example.com')
      expect(result).toBe(true)
    })

    test('should handle multiple comma-separated entries', () => {
      const noProxy = 'localhost,example.com,*.internal.com'

      expect(proxyUtils.shouldBypassProxy('https://localhost/api', noProxy)).toBe(true)
      expect(proxyUtils.shouldBypassProxy('https://example.com/api', noProxy)).toBe(true)
      expect(proxyUtils.shouldBypassProxy('https://api.internal.com/test', noProxy)).toBe(true)
      expect(proxyUtils.shouldBypassProxy('https://external.com/api', noProxy)).toBe(false)
    })

    test('should handle empty entries in NO_PROXY list', () => {
      const result = proxyUtils.shouldBypassProxy('https://example.com/api', 'localhost,,example.com')
      expect(result).toBe(true)
    })
  })
})
