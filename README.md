# Black Duck Security Scan

**NOTE:** If you are currently using the old Synopsys Action, please follow these <a href="https://community.blackduck.com/s/article/integrations-black-duck-migration-instructions">instructions</a> to migrate from Synopsys Action to this new Black Duck Security Scan Action. 

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/blackduck-inc/black-duck-security-scan?color=blue&label=Latest%20Version&sort=semver)

Black Duck Security Action allows you to integrate Static Analysis Security Testing (SAST) and Software Composition Analysis (SCA) into your CI/CD pipelines. Black Duck Security Action leverages Bridge-CLI, a foundational piece of technology that has built-in knowledge of how to run all major black duck security testing solutions, plus common workflows for platforms like GitHub.

To use Black Duck Security Action, please follow the steps below:

1. Configure GitHub as described in the [GitHub Prerequisites](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_github-prerequisites.html) page.
  
2. Install and configure Black Duck Security Action for the Black Duck product you are using. <br/>
Polaris - [Quick Start Guide](https://documentation.blackduck.com/bundle/bridge/page/documentation/t_github-polaris-quickstart.html) | [Reference page](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_github-polaris.html) <br/>
Black Duck SCA - [Quick Start Guide](https://documentation.blackduck.com/bundle/bridge/page/documentation/t_github-blackduck-quickstart.html) | [Reference Page](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_github-blackduck.html)  <br/>
Coverity - [Quick Start Guide](https://documentation.blackduck.com/bundle/bridge/page/documentation/t_github-coverity-quickstart.html) | [Reference Page](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_github-coverity.html) <br/>
SRM - [Quick Start Guide](https://documentation.blackduck.com/bundle/bridge/page/documentation/t_github-srm-quickstart.html) | [Reference Page](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_github-srm.html) <br/>

3. For additional configuration options, visit the [Additional GitHub Configuration](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_additional-github-parameters.html) page.

As an alternative to Black Duck Security Action, you also have the option to use Bridge CLI. <br/>
Detailed documentation for Bridge CLI can be found [here](https://documentation.blackduck.com/bundle/bridge/page/documentation/c_overview.html).
