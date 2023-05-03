# Changelog
Noteworthy changes to the agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
### Changed
### Fixed
### Removed

## [1.0.1-limited-preview] - 2023-04-20

### Added
- More instrumentations added wrt to APM
- Thread Name Changes from K2 to NR-CSEC
- Non-Blocking initial WS connection to address NR-107536 : APM Integration test failure due to WS

### Fixed
- Add handling for passing the license key in quotes
- NR-103217 Events for jetty 9 not getting generated.
- NR-103233, removed dependency of java.lang.management by oshi library.
- Minor fix to URLConnection_Instrumentation regarding empty url.
- NR-93687, add excludes of Specific InputStream classes, invoke getTransaction for preload of Transaction classes
- Xpath update incorrect return types of inst methods
- Removed java.io.FileSystem Hooks since those are covered in java.io.File inst. Works around NR-98829
- NR-106418, update JSON converter to include null values also.


## [1.0.0-limited-preview] - 2023-02-23

### Added
- Add debug level env variables for log file size and count manipulations NR_CSEC_DEBUG_LOGFILE_SIZE & NR_CSEC_DEBUG_LOGFILE_MAX_COUNT
- Rename healthcheck field from stat to stats
- Websocket connection now support custom ca certificate
- Added data member isIASTRequest in base of JavaAgentEventBean
- Changes to APM code: now only loading CSEC components if agent config has ‘security.enable’ value defined.
- Changes to user code detection hooks in CSEC. Now able to point servlet annotated classes and extension of HttpServlet do* methods.
- Fixed verify error with all mongo version, added instrumentation for mongo 3.1.x
- Added Let's Encrypt CA to trust store for prod clusters.
- Added options to provide custom trust CA via agent config('security.ca_bundle_path') and env parameter('NEW_RELIC_SECURITY_CA_BUNDLE_PATH'). This var takes path accessible to collector and expects a pem file.
- Reset CSEC component version to 1.0.0
- Reset CSEC json version to 1.0.0
- Set WS TCP connect timeout to 15
- Update WS header to include correct NR-LICENSE-KEY & NR-AGENT-RUN-TOKEN