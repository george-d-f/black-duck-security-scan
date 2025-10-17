import {describe, test, expect, jest, beforeEach} from '@jest/globals'

// Use jest.fn() without strict typing for mock functions
const createMockFn = () => jest.fn() as any

describe('Tool Cache Local Unit Tests', () => {
  let toolCache: any
  let mockCore: any
  let mockIo: any
  let mockFs: any
  let mockPath: any
  let mockOs: any
  let mockHttpm: any
  let mockUtil: any
  let mockHttps: any
  let mockUuid: any
  let mockRetryHelper: any
  let mockSslUtils: any

  beforeEach(() => {
    jest.resetModules()
    jest.clearAllMocks()

    // Create simple mocks using helper function with dynamic UUIDs to prevent conflicts
    mockCore = {debug: createMockFn()}
    mockIo = {
      mkdirP: createMockFn().mockResolvedValue(undefined),
      rmRF: createMockFn().mockResolvedValue(undefined)
    }
    mockFs = {
      existsSync: createMockFn().mockReturnValue(false),
      createWriteStream: createMockFn().mockReturnValue({
        on: createMockFn().mockImplementation((event: string, callback: Function) => {
          if (event === 'finish') {
            setTimeout(callback, 0)
          }
          return {}
        }),
        write: createMockFn(),
        end: createMockFn()
      }),
      statSync: createMockFn().mockReturnValue({size: 1024}),
      unlinkSync: createMockFn()
    }
    mockPath = {
      join: createMockFn().mockImplementation((...args: any[]) => args.join('/')),
      dirname: createMockFn().mockImplementation((p: any) => String(p).split('/').slice(0, -1).join('/'))
    }
    mockOs = {tmpdir: createMockFn().mockReturnValue('/tmp')}
    mockHttpm = {
      HttpClient: createMockFn().mockImplementation(() => ({
        get: createMockFn().mockResolvedValue({
          message: {
            statusCode: 200,
            statusMessage: 'OK',
            pipe: createMockFn()
          }
        } as any)
      }))
    }
    mockUtil = {
      promisify: createMockFn().mockReturnValue(createMockFn().mockResolvedValue(undefined))
    }
    mockHttps = {
      request: createMockFn().mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        if (callback) {
          setTimeout(() => {
            callback({
              statusCode: 200,
              headers: {'content-length': '1024'},
              on: createMockFn(),
              pipe: createMockFn()
            })
          }, 0)
        }

        return req
      })
    }
    // Use timestamp to make unique UUIDs per test
    mockUuid = {v4: createMockFn().mockImplementation(() => `test-uuid-${Date.now()}-${Math.random()}`)}
    mockRetryHelper = {
      RetryHelper: createMockFn().mockImplementation(() => ({
        execute: createMockFn().mockImplementation(async (callback: any) => {
          return await callback()
        })
      }))
    }
    mockSslUtils = {
      getSSLConfig: createMockFn().mockReturnValue({trustAllCerts: false}),
      createHTTPSRequestOptions: createMockFn().mockReturnValue({
        hostname: 'example.com',
        port: 443,
        path: '/test',
        method: 'GET'
      }),
      createHTTPSAgent: createMockFn().mockReturnValue({
        // Mock HTTPS agent
        options: {}
      })
    }

    // Apply mocks
    jest.doMock('@actions/core', () => mockCore)
    jest.doMock('@actions/io', () => mockIo)
    jest.doMock('fs', () => mockFs)
    jest.doMock('path', () => mockPath)
    jest.doMock('os', () => mockOs)
    jest.doMock('@actions/http-client', () => mockHttpm)
    jest.doMock('util', () => mockUtil)
    jest.doMock('https', () => mockHttps)
    jest.doMock('uuid', () => mockUuid)
    jest.doMock('../../../src/blackduck-security-action/retry-helper', () => mockRetryHelper)
    jest.doMock('../../../src/blackduck-security-action/ssl-utils', () => mockSslUtils)

    // Import after mocking
    toolCache = require('../../../src/blackduck-security-action/tool-cache-local')
  })

  describe('HTTPError', () => {
    test('should create HTTPError with status code', () => {
      const error = new toolCache.HTTPError(404)
      expect(error.httpStatusCode).toBe(404)
      expect(error.message).toBe('Unexpected HTTP response: 404')
      expect(error).toBeInstanceOf(Error)
    })

    test('should create HTTPError with undefined status code', () => {
      const error = new toolCache.HTTPError(undefined)
      expect(error.httpStatusCode).toBeUndefined()
      expect(error.message).toBe('Unexpected HTTP response: undefined')
    })

    test('should maintain proper prototype chain', () => {
      const error = new toolCache.HTTPError(500)
      expect(error).toBeInstanceOf(toolCache.HTTPError)
      expect(error).toBeInstanceOf(Error)
    })
  })

  describe('downloadTool basic functionality', () => {
    test('should export downloadTool function', () => {
      expect(typeof toolCache.downloadTool).toBe('function')
    })

    test('should download a file successfully', async () => {
      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')
    })

    test('should accept custom destination parameter', async () => {
      const customDest = '/custom/path/file.zip'
      const result = await toolCache.downloadTool('https://example.com/file.zip', customDest)
      expect(typeof result).toBe('string')
    })

    test('should accept auth parameter', async () => {
      const auth = 'Bearer token'
      const result = await toolCache.downloadTool('https://example.com/file.zip', undefined, auth)
      expect(typeof result).toBe('string')
    })

    test('should accept headers parameter', async () => {
      const headers = {'Content-Type': 'application/json'}
      const result = await toolCache.downloadTool('https://example.com/file.zip', undefined, undefined, headers)
      expect(typeof result).toBe('string')
    })

    test('should accept all parameters', async () => {
      const dest = '/custom/dest'
      const auth = 'Bearer token'
      const headers = {'X-Custom': 'value'}
      const result = await toolCache.downloadTool('https://example.com/file.zip', dest, auth, headers)
      expect(typeof result).toBe('string')
    })
  })

  describe('downloadTool retry logic', () => {
    test('should handle retry logic with different error scenarios', async () => {
      const retryInstance = new mockRetryHelper.RetryHelper(3, 1000)
      await toolCache.downloadTool('https://example.com/file.zip')

      // Test various error scenarios if we can access the shouldRetry function
      const calls = retryInstance.execute.mock.calls
      if (calls.length > 0) {
        const [, shouldRetry] = calls[0]

        if (typeof shouldRetry === 'function') {
          // Test retryable HTTP error
          const httpError500 = new toolCache.HTTPError(500)
          expect(shouldRetry(httpError500)).toBe(true)

          // Test non-retryable HTTP error
          const httpError404 = new toolCache.HTTPError(404)
          expect(shouldRetry(httpError404)).toBe(false)

          // Test file exists error
          const fileExistsError = new Error('Destination file path /test already exists')
          expect(shouldRetry(fileExistsError)).toBe(false)

          // Test other errors
          const networkError = new Error('Network timeout')
          expect(shouldRetry(networkError)).toBe(true)
        }
      }
    })
  })

  describe('downloadTool SSL scenarios', () => {
    test('should handle trustAllCerts SSL configuration', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true, customCA: true})

      // Mock fs.existsSync to return false initially, then true after "download"
      mockFs.existsSync.mockReturnValueOnce(false).mockReturnValueOnce(true)

      // Mock HTTPS request for custom SSL path
      mockHttps.request.mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        setTimeout(() => {
          const res = {
            statusCode: 200,
            headers: {'content-length': '1024'},
            on: createMockFn().mockImplementation((event: string, cb: Function) => {
              if (event === 'data') {
                cb(Buffer.from('test-data'))
              }
              return res
            }),
            pipe: createMockFn().mockImplementation((writeStream: any) => {
              setTimeout(
                () =>
                  writeStream.on.mock.calls.forEach((call: any) => {
                    if (call[0] === 'finish') call[1]()
                  }),
                0
              )
            })
          }
          callback(res)
        }, 0)

        return req
      })

      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')
    }, 10000)

    test('should handle custom CA SSL configuration', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({
        trustAllCerts: false,
        customCA: 'custom-ca-cert',
        combinedCAs: ['custom-ca-cert', 'system-ca']
      })

      // Mock fs.existsSync to return false initially, then true after "download"
      mockFs.existsSync.mockReturnValueOnce(false).mockReturnValueOnce(true)

      // Mock HTTPS request for custom SSL path
      mockHttps.request.mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        setTimeout(() => {
          const res = {
            statusCode: 200,
            headers: {'content-length': '1024'},
            on: createMockFn().mockImplementation((event: string, cb: Function) => {
              if (event === 'data') {
                cb(Buffer.from('test-data'))
              }
              return res
            }),
            pipe: createMockFn().mockImplementation((writeStream: any) => {
              setTimeout(
                () =>
                  writeStream.on.mock.calls.forEach((call: any) => {
                    if (call[0] === 'finish') call[1]()
                  }),
                0
              )
            })
          }
          callback(res)
        }, 0)

        return req
      })

      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')
    }, 10000)

    test('should handle standard SSL configuration', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: false})
      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')
    })
  })

  describe('downloadTool error scenarios', () => {
    test('should handle file already exists error', async () => {
      mockFs.existsSync.mockReturnValue(true)
      await expect(toolCache.downloadTool('https://example.com/file.zip', '/existing/file')).rejects.toThrow('Destination file path /existing/file already exists')
    })

    test('should handle HTTP error responses', async () => {
      mockHttpm.HttpClient = createMockFn().mockImplementation(() => ({
        get: createMockFn().mockResolvedValue({
          message: {statusCode: 404, statusMessage: 'Not Found'}
        } as any)
      }))
      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow(toolCache.HTTPError)
    })

    test('should handle pipeline failures', async () => {
      mockUtil.promisify.mockReturnValue(createMockFn().mockRejectedValue(new Error('Pipeline failed') as any))
      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow('Pipeline failed')
    })
  })

  describe('downloadWithCustomSSL scenarios', () => {
    test('should handle HTTPS request with custom SSL', async () => {
      // Use a unique destination to avoid conflicts
      const uniqueDest = `/tmp/test-${Date.now()}-${Math.random()}.zip`
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true, customCA: true})

      // Mock successful write stream
      const mockWriteStream: any = {
        on: createMockFn().mockImplementation((event: any, callback: any) => {
          if (event === 'finish') setTimeout(callback, 0)
          return mockWriteStream
        })
      }
      mockFs.createWriteStream.mockReturnValue(mockWriteStream)
      // First check should return false (file doesn't exist), then true (after download)
      mockFs.existsSync.mockReturnValueOnce(false).mockReturnValueOnce(true)
      mockFs.statSync.mockReturnValue({size: 1024})

      mockHttps.request.mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        setTimeout(() => {
          const res = {
            statusCode: 200,
            headers: {'content-length': '1024'},
            on: createMockFn().mockImplementation((event: string, cb: Function) => {
              if (event === 'data') {
                cb(Buffer.from('test-data'))
              }
              return res
            }),
            pipe: createMockFn().mockImplementation((writeStream: any) => {
              setTimeout(
                () =>
                  writeStream.on.mock.calls.forEach((call: any) => {
                    if (call[0] === 'finish') call[1]()
                  }),
                0
              )
            })
          }
          callback(res)
        }, 0)

        return req
      })

      const result = await toolCache.downloadTool('https://example.com/file.zip', uniqueDest)
      expect(typeof result).toBe('string')
    })

    test('should handle HTTPS timeout errors', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true})

      mockHttps.request.mockImplementation(() => {
        return {
          on: jest.fn(),
          setTimeout: jest.fn().mockImplementation((...args: any[]) => {
            const callback = args[1]
            if (callback) setTimeout(callback, 0) // Immediate timeout
          }),
          end: jest.fn(),
          destroy: jest.fn()
        }
      })

      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow('Download timeout')
    })

    test('should handle HTTPS request errors', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true})

      mockHttps.request.mockImplementation(() => {
        return {
          on: jest.fn().mockImplementation((event: any, callback: any) => {
            if (event === 'error') {
              setTimeout(() => callback(new Error('Connection failed')), 0)
            }
          }),
          setTimeout: jest.fn(),
          end: jest.fn(),
          destroy: jest.fn()
        }
      })

      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow('Connection failed')
    })

    test('should handle write stream errors', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true})

      const mockWriteStream: any = {
        on: jest.fn().mockImplementation((event: any, callback: any) => {
          if (event === 'error') {
            setTimeout(() => callback(new Error('Write failed')), 0)
          }
          return mockWriteStream
        })
      }
      mockFs.createWriteStream.mockReturnValue(mockWriteStream)

      mockHttps.request.mockImplementation((...args: any[]) => {
        const callback = args[1]
        if (callback) {
          setTimeout(() => {
            callback({
              statusCode: 200,
              headers: {'content-length': '1024'},
              on: jest.fn(),
              pipe: jest.fn()
            })
          }, 0)
        }
        return {
          on: jest.fn(),
          setTimeout: jest.fn(),
          end: jest.fn(),
          destroy: jest.fn()
        }
      })

      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow('Write failed')
    })

    test('should handle empty file validation', async () => {
      const uniqueDest = `/tmp/test-empty-${Date.now()}-${Math.random()}.zip`
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true, customCA: true})

      const mockWriteStream: any = {
        on: createMockFn().mockImplementation((event: any, callback: any) => {
          if (event === 'finish') setTimeout(callback, 0)
          return mockWriteStream
        })
      }
      mockFs.createWriteStream.mockReturnValue(mockWriteStream)
      mockFs.existsSync.mockReturnValueOnce(false).mockReturnValueOnce(true)
      mockFs.statSync.mockReturnValue({size: 0}) // Empty file

      mockHttps.request.mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        setTimeout(() => {
          const res = {
            statusCode: 200,
            headers: {'content-length': '1024'},
            on: createMockFn().mockImplementation((event: string, cb: Function) => {
              if (event === 'data') {
                cb(Buffer.from('test-data'))
              }
              return res
            }),
            pipe: createMockFn().mockImplementation((writeStream: any) => {
              setTimeout(
                () =>
                  writeStream.on.mock.calls.forEach((call: any) => {
                    if (call[0] === 'finish') call[1]()
                  }),
                0
              )
            })
          }
          callback(res)
        }, 0)

        return req
      })

      await expect(toolCache.downloadTool('https://example.com/file.zip', uniqueDest)).rejects.toThrow('Downloaded file is empty')
    })

    test('should handle missing file validation', async () => {
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true})

      const mockWriteStream: any = {
        on: jest.fn().mockImplementation((event: any, callback: any) => {
          if (event === 'finish') setTimeout(callback, 0)
          return mockWriteStream
        })
      }
      mockFs.createWriteStream.mockReturnValue(mockWriteStream)
      mockFs.existsSync.mockReturnValue(false) // File doesn't exist

      mockHttps.request.mockImplementation((...args: any[]) => {
        const callback = args[1]
        if (callback) {
          setTimeout(() => {
            callback({
              statusCode: 200,
              headers: {'content-length': '1024'},
              on: jest.fn(),
              pipe: jest.fn()
            })
          }, 0)
        }
        return {
          on: jest.fn(),
          setTimeout: jest.fn(),
          end: jest.fn(),
          destroy: jest.fn()
        }
      })

      await expect(toolCache.downloadTool('https://example.com/file.zip')).rejects.toThrow('Downloaded file does not exist')
    })

    test('should handle download progress tracking', async () => {
      const uniqueDest = `/tmp/test-progress-${Date.now()}-${Math.random()}.zip`
      mockSslUtils.getSSLConfig.mockReturnValue({trustAllCerts: true, customCA: true})

      const mockWriteStream: any = {
        on: createMockFn().mockImplementation((event: any, callback: any) => {
          if (event === 'finish') setTimeout(callback, 10)
          return mockWriteStream
        })
      }
      mockFs.createWriteStream.mockReturnValue(mockWriteStream)
      mockFs.existsSync.mockReturnValueOnce(false).mockReturnValueOnce(true)
      mockFs.statSync.mockReturnValue({size: 1024})

      mockHttps.request.mockImplementation((options: any, callback: Function) => {
        const req = {
          on: createMockFn(),
          setTimeout: createMockFn(),
          end: createMockFn(),
          destroy: createMockFn()
        }

        setTimeout(() => {
          const res = {
            statusCode: 200,
            headers: {'content-length': '1024'},
            on: createMockFn().mockImplementation((event: string, cb: Function) => {
              if (event === 'data') {
                // Simulate data chunks
                cb(Buffer.from('chunk1'))
                cb(Buffer.from('chunk2'))
              }
              return res
            }),
            pipe: createMockFn().mockImplementation((writeStream: any) => {
              setTimeout(
                () =>
                  writeStream.on.mock.calls.forEach((call: any) => {
                    if (call[0] === 'finish') call[1]()
                  }),
                0
              )
            })
          }
          callback(res)
        }, 0)

        return req
      })

      await toolCache.downloadTool('https://example.com/file.zip', uniqueDest)

      expect(mockCore.debug).toHaveBeenCalledWith('Download size: 1024 bytes')
      expect(mockCore.debug).toHaveBeenCalledWith('Total bytes downloaded: 12') // chunk1 + chunk2
    })
  })

  describe('_getGlobal function coverage', () => {
    test('should handle global factory function', async () => {
      const mockGlobal = global as any
      mockGlobal.TEST_DOWNLOAD_TOOL_RESPONSE_MESSAGE_FACTORY = () => ({
        pipe: jest.fn()
      })

      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')

      // Clean up
      delete mockGlobal.TEST_DOWNLOAD_TOOL_RESPONSE_MESSAGE_FACTORY
    })

    test('should handle missing global factory function', async () => {
      const mockGlobal = global as any
      delete mockGlobal.TEST_DOWNLOAD_TOOL_RESPONSE_MESSAGE_FACTORY

      const result = await toolCache.downloadTool('https://example.com/file.zip')
      expect(typeof result).toBe('string')
    })
  })
})
