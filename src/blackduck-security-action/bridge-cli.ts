import {exec, ExecOptions} from '@actions/exec'
import {BRIDGE_CLI_DOWNLOAD_URL, ENABLE_NETWORK_AIR_GAP, BRIDGE_CLI_INSTALL_DIRECTORY_KEY} from './inputs'
import {debug, error, info, warning} from '@actions/core'
import {GITHUB_ENVIRONMENT_VARIABLES, NON_RETRY_HTTP_CODES, RETRY_COUNT, RETRY_DELAY_IN_MILLISECONDS, BRIDGE_CLI_DEFAULT_PATH_LINUX, BRIDGE_CLI_DEFAULT_PATH_MAC, BRIDGE_CLI_DEFAULT_PATH_WINDOWS, MAC_PLATFORM_NAME, LINUX_PLATFORM_NAME, WINDOWS_PLATFORM_NAME} from '../application-constants'
import {tryGetExecutablePath} from '@actions/io/lib/io-util'
import path from 'path'
import {checkIfPathExists, cleanupTempDir, parseToBoolean, sleep, getSharedHttpsAgent} from './utility'
import * as https from 'https'
import * as url from 'url'
import * as inputs from './inputs'
import {DownloadFileResponse, extractZipped, getRemoteFile} from './download-utility'
import fs, {readFileSync} from 'fs'
import {validateBlackDuckInputs, validateCoverityInputs, validatePolarisInputs, validateSRMInputs, validateScanTypes} from './validators'
import {BridgeToolsParameter} from './tools-parameter'
import * as constants from '../application-constants'
import DomParser from 'dom-parser'
import os from 'os'
import semver from 'semver'
import {rmRF} from '@actions/io'

export class Bridge {
  bridgeExecutablePath: string
  bridgePath: string
  bridgeArtifactoryURL: string
  bridgeUrlPattern: string
  bridgeUrlLatestPattern: string
  WINDOWS_PLATFORM = 'win64'
  LINUX_PLATFORM = 'linux64'
  LINUX_ARM_PLATFORM = 'linux_arm'
  MAC_PLATFORM = 'macosx'
  MAC_ARM_PLATFORM = 'macos_arm'

  constructor() {
    this.bridgeExecutablePath = ''
    this.bridgePath = ''
    this.bridgeArtifactoryURL = constants.BRIDGE_CLI_ARTIFACTORY_URL
    this.bridgeUrlPattern = this.bridgeArtifactoryURL.concat('$version/bridge-cli-bundle-$version-$platform.zip')
    this.bridgeUrlLatestPattern = this.bridgeArtifactoryURL.concat('latest/bridge-cli-bundle-$platform.zip')
  }

  private getBridgeDefaultPath(): string {
    let bridgeDefaultPath = ''
    const subFolder = 'bridge-cli-bundle-'.concat(this.getOSPlatform())
    const osName = process.platform
    if (osName === MAC_PLATFORM_NAME) {
      bridgeDefaultPath = path.join(process.env['HOME'] as string, BRIDGE_CLI_DEFAULT_PATH_MAC, subFolder)
    } else if (osName === LINUX_PLATFORM_NAME) {
      bridgeDefaultPath = path.join(process.env['HOME'] as string, BRIDGE_CLI_DEFAULT_PATH_LINUX, subFolder)
    } else if (osName === WINDOWS_PLATFORM_NAME) {
      bridgeDefaultPath = path.join(process.env['USERPROFILE'] as string, BRIDGE_CLI_DEFAULT_PATH_WINDOWS, subFolder)
    }

    return bridgeDefaultPath
  }
  private getBridgeCLIDownloadDefaultPath(): string {
    let bridgeCLIDefaultPath = ''
    const osName = process.platform
    if (osName === MAC_PLATFORM_NAME) {
      bridgeCLIDefaultPath = path.join(process.env['HOME'] as string, BRIDGE_CLI_DEFAULT_PATH_MAC)
    } else if (osName === LINUX_PLATFORM_NAME) {
      bridgeCLIDefaultPath = path.join(process.env['HOME'] as string, BRIDGE_CLI_DEFAULT_PATH_LINUX)
    } else if (osName === WINDOWS_PLATFORM_NAME) {
      bridgeCLIDefaultPath = path.join(process.env['USERPROFILE'] as string, BRIDGE_CLI_DEFAULT_PATH_WINDOWS)
    }

    return bridgeCLIDefaultPath
  }
  async checkIfBridgeExists(bridgeVersion: string): Promise<boolean> {
    await this.validateBridgePath()
    const osName = process.platform
    let versionFilePath = ''
    let versionFileExists = false
    if (osName === WINDOWS_PLATFORM_NAME) {
      versionFilePath = this.bridgePath.concat('\\versions.txt')
      versionFileExists = checkIfPathExists(versionFilePath)
    } else {
      versionFilePath = this.bridgePath.concat('/versions.txt')
      versionFileExists = checkIfPathExists(versionFilePath)
    }
    if (versionFileExists) {
      debug('Version file found at '.concat(this.bridgePath))
      if (await this.checkIfVersionExists(bridgeVersion, versionFilePath)) {
        return true
      }
    } else {
      debug('Bridge CLI version file could not be found at '.concat(this.bridgePath))
    }

    return false
  }

  async executeBridgeCommand(bridgeCommand: string, workingDirectory: string): Promise<number> {
    const osName: string = process.platform
    await this.setBridgeExecutablePath()
    debug('Bridge executable path:'.concat(this.bridgePath))
    if (!this.bridgeExecutablePath) {
      throw new Error(constants.BRIDGE_EXECUTABLE_NOT_FOUND_ERROR.concat(this.bridgePath))
    }
    if (osName === MAC_PLATFORM_NAME || osName === LINUX_PLATFORM_NAME || osName === WINDOWS_PLATFORM_NAME) {
      const exectOp: ExecOptions = {
        cwd: workingDirectory
      }
      try {
        return await exec(this.bridgeExecutablePath.concat(' ', bridgeCommand), [], exectOp)
      } catch (errorObject) {
        throw errorObject
      }
    }
    return -1
  }

  async downloadBridge(tempDir: string): Promise<void> {
    try {
      // Automatically configure bridge if Bridge download url is provided
      let bridgeUrl = ''
      let bridgeVersion = ''
      if (inputs.BRIDGE_CLI_DOWNLOAD_URL) {
        bridgeUrl = BRIDGE_CLI_DOWNLOAD_URL
        const versionInfo = bridgeUrl.match('.*bridge-cli-bundle-([0-9.]+[a-zA-Z0-9]*).*')
        if (versionInfo != null) {
          bridgeVersion = versionInfo[1]
          if (!bridgeVersion) {
            const regex = /\w*(bridge-cli-bundle-(win64|linux64|linux_arm|macosx|macos_arm).zip)/
            bridgeVersion = await this.getBridgeVersionFromLatestURL(bridgeUrl.replace(regex, 'versions.txt'))
          }
        }
      } else if (inputs.BRIDGE_CLI_DOWNLOAD_VERSION) {
        if (await this.validateBridgeVersion(inputs.BRIDGE_CLI_DOWNLOAD_VERSION)) {
          bridgeUrl = this.getVersionUrl(inputs.BRIDGE_CLI_DOWNLOAD_VERSION).trim()
          bridgeVersion = inputs.BRIDGE_CLI_DOWNLOAD_VERSION
        } else {
          return Promise.reject(new Error(constants.BRIDGE_VERSION_NOT_FOUND_ERROR))
        }
      } else {
        info('Checking for latest version of Bridge to download and configure')
        bridgeVersion = await this.getBridgeVersionFromLatestURL(this.bridgeArtifactoryURL.concat('latest/versions.txt'))
        bridgeUrl = this.getLatestVersionUrl()
      }
      info('Bridge CLI version is - '.concat(bridgeVersion))
      if (!(await this.checkIfBridgeExists(bridgeVersion))) {
        info('Downloading and configuring Bridge from URL - '.concat(bridgeUrl))
        const downloadResponse: DownloadFileResponse = await getRemoteFile(tempDir, bridgeUrl)
        let pathSeprator = ''
        if (process.platform === WINDOWS_PLATFORM_NAME) {
          pathSeprator = `\\`
        } else if (process.platform === MAC_PLATFORM_NAME || process.platform === LINUX_PLATFORM_NAME) {
          pathSeprator = `/`
        }
        const extractZippedFilePath: string = BRIDGE_CLI_INSTALL_DIRECTORY_KEY || this.getBridgeCLIDownloadDefaultPath()
        this.bridgePath = path.join(extractZippedFilePath, 'bridge-cli-bundle-'.concat(this.getOSPlatform()))
        // Clear the existing bridge, if available so we will not have duplicate or extra bridge folder
        info('Clear the existing bridge folder, if available from '.concat(this.bridgePath))
        if (fs.existsSync(this.bridgePath)) {
          await rmRF(this.bridgePath)
        }
        await extractZipped(downloadResponse.filePath, extractZippedFilePath)
        const sourceFile = extractZippedFilePath
          .concat(pathSeprator)
          .concat(downloadResponse.filePath.split(pathSeprator).pop() as string)
          .split('.zip')[0]
        debug('Rename folder from '.concat(sourceFile).concat(' to ').concat(this.bridgePath))
        fs.renameSync(sourceFile, this.bridgePath)
        info('Download and configuration of Bridge CLI completed')
      } else {
        info('Bridge CLI already exists, download has been skipped')
      }
    } catch (e) {
      const errorObject = (e as Error).message
      await cleanupTempDir(tempDir)
      if (errorObject.includes('404') || errorObject.toLowerCase().includes('invalid url')) {
        let runnerOS = ''
        if (process.env['RUNNER_OS']) {
          runnerOS = process.env['RUNNER_OS']
        }
        return Promise.reject(new Error(constants.BRIDGE_CLI_URL_NOT_VALID_OS_ERROR.concat(runnerOS, ' runner')))
      } else if (errorObject.toLowerCase().includes('empty')) {
        return Promise.reject(new Error(constants.PROVIDED_BRIDGE_CLI_URL_EMPTY_ERROR))
      } else {
        return Promise.reject(new Error(errorObject))
      }
    }
  }

  async prepareCommand(tempDir: string): Promise<string> {
    try {
      let formattedCommand = ''
      const invalidParams: string[] = validateScanTypes()
      if (invalidParams.length === 4) {
        return Promise.reject(new Error(constants.SCAN_TYPE_REQUIRED_ERROR.replace('{0}', constants.POLARIS_SERVER_URL_KEY).replace('{1}', constants.COVERITY_URL_KEY).replace('{2}', constants.BLACKDUCKSCA_URL_KEY).replace('{3}', constants.SRM_URL_KEY)))
      }

      // Validate ssl cert and trust all certs validation
      if (inputs.NETWORK_SSL_CERT_FILE && inputs.NETWORK_SSL_TRUST_ALL === 'true') {
        return Promise.reject(new Error(constants.NETWORK_SSL_VALIDATION_ERROR_MESSAGE))
      }

      const githubRepo = process.env[GITHUB_ENVIRONMENT_VARIABLES.GITHUB_REPOSITORY]
      const githubRepoName = githubRepo !== undefined ? githubRepo.substring(githubRepo.indexOf('/') + 1, githubRepo.length).trim() : ''

      // validating and preparing command for polaris
      const polarisErrors: string[] = validatePolarisInputs()

      if (polarisErrors.length === 0 && inputs.POLARIS_SERVER_URL) {
        const polarisCommandFormatter = new BridgeToolsParameter(tempDir)
        formattedCommand = formattedCommand.concat(polarisCommandFormatter.getFormattedCommandForPolaris(githubRepoName))
      }

      // validating and preparing command for coverity
      const coverityErrors: string[] = validateCoverityInputs()
      if (coverityErrors.length === 0 && inputs.COVERITY_URL) {
        const coverityCommandFormatter = new BridgeToolsParameter(tempDir)
        formattedCommand = formattedCommand.concat(coverityCommandFormatter.getFormattedCommandForCoverity(githubRepoName))
      }

      // validating and preparing command for blackduck
      const blackduckErrors: string[] = validateBlackDuckInputs()
      if (blackduckErrors.length === 0 && inputs.BLACKDUCKSCA_URL) {
        const blackDuckCommandFormatter = new BridgeToolsParameter(tempDir)
        formattedCommand = formattedCommand.concat(blackDuckCommandFormatter.getFormattedCommandForBlackduck())
      }

      // validating and preparing command for SRM
      const srmErrors: string[] = validateSRMInputs()
      if (srmErrors.length === 0 && inputs.SRM_URL) {
        const srmCommandFormatter = new BridgeToolsParameter(tempDir)
        formattedCommand = formattedCommand.concat(srmCommandFormatter.getFormattedCommandForSRM(githubRepoName))
      }

      let validationErrors: string[] = []
      validationErrors = validationErrors.concat(polarisErrors)
      validationErrors = validationErrors.concat(coverityErrors)
      validationErrors = validationErrors.concat(blackduckErrors)
      validationErrors = validationErrors.concat(srmErrors)
      if (formattedCommand.length === 0) {
        return Promise.reject(new Error(validationErrors.join(',')))
      }
      if (validationErrors.length > 0) {
        error(new Error(validationErrors.join(',')))
      }

      if (parseToBoolean(inputs.INCLUDE_DIAGNOSTICS)) {
        formattedCommand = formattedCommand.concat(BridgeToolsParameter.SPACE).concat(BridgeToolsParameter.DIAGNOSTICS_OPTION)
      }

      debug('Formatted command is - '.concat(formattedCommand))
      return formattedCommand
    } catch (e) {
      const errorObject = e as Error
      await cleanupTempDir(tempDir)
      debug(errorObject.stack === undefined ? '' : errorObject.stack.toString())
      return Promise.reject(errorObject)
    }
  }

  async getAllAvailableBridgeVersions(): Promise<string[]> {
    let htmlResponse = ''

    let retryCountLocal = RETRY_COUNT
    let retryDelay = RETRY_DELAY_IN_MILLISECONDS
    let statusCode: number
    const versionArray: string[] = []

    do {
      try {
        const response = await this.makeHttpsGetRequest(this.bridgeArtifactoryURL)
        statusCode = response.statusCode
        htmlResponse = response.body

        if (!NON_RETRY_HTTP_CODES.has(Number(statusCode))) {
          retryDelay = await this.retrySleepHelper('Getting all available bridge versions has been failed, Retries left: ', retryCountLocal, retryDelay)
          retryCountLocal--
        } else {
          retryCountLocal = 0

          const domParser = new DomParser()
          const doms = domParser.parseFromString(htmlResponse)
          const elems = doms.getElementsByTagName('a') //querySelectorAll('a')

          if (elems != null) {
            for (const el of elems) {
              const content = el.textContent
              if (content != null) {
                const v = content.match('^[0-9]+.[0-9]+.[0-9]+')

                if (v != null && v.length === 1) {
                  versionArray.push(v[0])
                }
              }
            }
          }
        }
      } catch (err) {
        retryDelay = await this.retrySleepHelper('Getting all available bridge versions has been failed, Retries left: ', retryCountLocal, retryDelay)
        retryCountLocal--
      }

      if (retryCountLocal === 0 && !(versionArray.length > 0)) {
        warning('Unable to retrieve the Bridge Versions from Artifactory')
      }
    } while (retryCountLocal > 0)
    return versionArray
  }

  async validateBridgeVersion(version: string): Promise<boolean> {
    const versions = await this.getAllAvailableBridgeVersions()
    return versions.includes(version.trim())
  }

  // Helper function to select the platform based on the version and architecture and log fallback
  private selectPlatform(version: string, isARM: boolean, isValidVersionForARM: boolean, armPlatform: string, defaultPlatform: string, minVersion: string): string {
    if (isARM && !isValidVersionForARM) {
      info(`Detected Bridge CLI version (${version}) below the minimum ARM support requirement (${minVersion}). Defaulting to ${defaultPlatform} platform.`)
      return defaultPlatform
    }
    return isARM && isValidVersionForARM ? armPlatform : defaultPlatform
  }

  getVersionUrl(version: string): string {
    const osName = process.platform

    let bridgeDownloadUrl = this.bridgeUrlPattern.replace('$version', version)
    bridgeDownloadUrl = bridgeDownloadUrl.replace('$version', version)
    if (osName === MAC_PLATFORM_NAME) {
      const isARM = !os.cpus()[0].model.includes('Intel')
      const isValidVersionForARM = semver.gte(version, constants.MIN_SUPPORTED_BRIDGE_CLI_MAC_ARM_VERSION)
      const platform = this.selectPlatform(version, isARM, isValidVersionForARM, this.MAC_ARM_PLATFORM, this.MAC_PLATFORM, constants.MIN_SUPPORTED_BRIDGE_CLI_MAC_ARM_VERSION)
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', platform)
    } else if (osName === LINUX_PLATFORM_NAME) {
      const isARM = /^(arm.*|aarch.*)$/.test(process.arch)
      const isValidVersionForARM = semver.gte(version, constants.MIN_SUPPORTED_BRIDGE_CLI_LINUX_ARM_VERSION)
      const platform = this.selectPlatform(version, isARM, isValidVersionForARM, this.LINUX_ARM_PLATFORM, this.LINUX_PLATFORM, constants.MIN_SUPPORTED_BRIDGE_CLI_LINUX_ARM_VERSION)
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', platform)
    } else if (osName === WINDOWS_PLATFORM_NAME) {
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', this.WINDOWS_PLATFORM)
    }

    return bridgeDownloadUrl
  }

  getLatestVersionUrl(): string {
    const osName = process.platform
    let bridgeDownloadUrl = this.bridgeUrlLatestPattern
    if (osName === MAC_PLATFORM_NAME) {
      const isARM = !os.cpus()[0].model.includes('Intel')
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', isARM ? this.MAC_ARM_PLATFORM : this.MAC_PLATFORM)
    } else if (osName === LINUX_PLATFORM_NAME) {
      const isARM = /^(arm.*|aarch.*)$/.test(process.arch)
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', isARM ? this.LINUX_ARM_PLATFORM : this.LINUX_PLATFORM)
    } else if (osName === WINDOWS_PLATFORM_NAME) {
      bridgeDownloadUrl = bridgeDownloadUrl.replace('$platform', this.WINDOWS_PLATFORM)
    }

    return bridgeDownloadUrl
  }
  getOSPlatform(): string {
    const osName = process.platform
    let osPlatform = ''
    if (osName === MAC_PLATFORM_NAME) {
      const isARM = !os.cpus()[0].model.includes('Intel')
      osPlatform = isARM ? this.MAC_ARM_PLATFORM : this.MAC_PLATFORM
    } else if (osName === LINUX_PLATFORM_NAME) {
      const isARM = /^(arm.*|aarch.*)$/.test(process.arch)
      osPlatform = isARM ? this.LINUX_ARM_PLATFORM : this.LINUX_PLATFORM
    } else if (osName === WINDOWS_PLATFORM_NAME) {
      osPlatform = this.WINDOWS_PLATFORM
    }

    return osPlatform
  }

  async checkIfVersionExists(bridgeVersion: string, bridgeVersionFilePath: string): Promise<boolean> {
    try {
      const contents = readFileSync(bridgeVersionFilePath, 'utf-8')
      return contents.includes('bridge-cli-bundle: '.concat(bridgeVersion))
    } catch (e) {
      info('Error reading version file content: '.concat((e as Error).message))
    }
    return false
  }

  async getBridgePath(): Promise<string> {
    let bridgePath = BRIDGE_CLI_INSTALL_DIRECTORY_KEY

    if (!bridgePath) {
      bridgePath = this.getBridgeDefaultPath()
    }
    return bridgePath
  }

  async getBridgeVersionFromLatestURL(latestVersionsUrl: string): Promise<string> {
    try {
      let retryCountLocal = RETRY_COUNT
      let retryDelay = RETRY_DELAY_IN_MILLISECONDS

      do {
        try {
          const response = await this.makeHttpsGetRequest(latestVersionsUrl)

          if (!NON_RETRY_HTTP_CODES.has(Number(response.statusCode))) {
            retryDelay = await this.retrySleepHelper('Getting latest Bridge CLI versions has been failed, Retries left: ', retryCountLocal, retryDelay)
            retryCountLocal--
          } else if (response.statusCode === 200) {
            retryCountLocal = 0
            const htmlResponse = response.body.trim()
            const lines = htmlResponse.split('\n')
            for (const line of lines) {
              if (line.includes('bridge-cli-bundle')) {
                return line.split(':')[1].trim()
              }
            }
          }
        } catch (err) {
          retryDelay = await this.retrySleepHelper('Getting latest Bridge CLI versions has been failed, Retries left: ', retryCountLocal, retryDelay)
          retryCountLocal--
        }

        if (retryCountLocal === 0) {
          warning('Unable to retrieve the most recent version from Artifactory URL')
        }
      } while (retryCountLocal > 0)
    } catch (e) {
      debug('Error reading version file content: '.concat((e as Error).message))
    }
    return ''
  }

  async validateBridgePath(): Promise<void> {
    this.bridgePath = this.getBridgeDefaultPath()
    if (BRIDGE_CLI_INSTALL_DIRECTORY_KEY) {
      this.bridgePath = BRIDGE_CLI_INSTALL_DIRECTORY_KEY
      if (!checkIfPathExists(this.bridgePath)) {
        throw new Error(constants.BRIDGE_INSTALL_DIRECTORY_NOT_FOUND_ERROR)
      }
      let folderName = 'bridge-cli-bundle-'.concat(this.getOSPlatform())
      if (process.platform === WINDOWS_PLATFORM_NAME) {
        folderName = `\\${folderName}`
      } else if (process.platform === MAC_PLATFORM_NAME || process.platform === LINUX_PLATFORM_NAME) {
        folderName = `/${folderName}`
      }
      if (checkIfPathExists(BRIDGE_CLI_INSTALL_DIRECTORY_KEY.concat(folderName))) {
        this.bridgePath = BRIDGE_CLI_INSTALL_DIRECTORY_KEY.concat(folderName)
      }
    } else {
      if (ENABLE_NETWORK_AIR_GAP && !checkIfPathExists(this.getBridgeDefaultPath())) {
        throw new Error(constants.BRIDGE_DEFAULT_DIRECTORY_NOT_FOUND_ERROR)
      }
    }
  }

  private async setBridgeExecutablePath(): Promise<void> {
    if (process.platform === WINDOWS_PLATFORM_NAME) {
      this.bridgeExecutablePath = await tryGetExecutablePath(this.bridgePath.concat('\\bridge-cli'), ['.exe'])
    } else if (process.platform === MAC_PLATFORM_NAME || process.platform === LINUX_PLATFORM_NAME) {
      this.bridgeExecutablePath = await tryGetExecutablePath(this.bridgePath.concat('/bridge-cli'), [])
    }
  }
  private async retrySleepHelper(message: string, retryCountLocal: number, retryDelay: number): Promise<number> {
    info(
      message
        .concat(String(retryCountLocal))
        .concat(', Waiting: ')
        .concat(String(retryDelay / 1000))
        .concat(' Seconds')
    )
    await sleep(retryDelay)
    // Delayed exponentially starting from 15 seconds
    retryDelay = retryDelay * 2
    return retryDelay
  }

  private async makeHttpsGetRequest(targetUrl: string): Promise<{statusCode: number; body: string}> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new url.URL(targetUrl)
      const agent = getSharedHttpsAgent(targetUrl)

      const requestOptions: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        agent,
        headers: {
          Accept: 'text/html',
          'User-Agent': 'BlackDuckSecurityAction'
        }
      }

      const req = https.request(requestOptions, res => {
        let body = ''

        res.on('data', chunk => {
          body += chunk
        })

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            body
          })
        })

        res.on('error', err => {
          reject(err)
        })
      })

      req.on('error', err => {
        reject(err)
      })

      req.setTimeout(30000, () => {
        req.destroy()
        reject(new Error('Request timeout'))
      })

      req.end()
    })
  }
}
