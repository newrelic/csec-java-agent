# Changelog
Noteworthy changes to the agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4-limited-preview] - 2023-06-19
### Changes
- Limiting the supported version range for Apache log4j due to the new version release of Apache log4j on 21 June 2023
- Support for indication what all API-IDs are scanned or being scanned.

## [1.0.3-limited-preview] - 2023-05-23
### Changes
- License update
- Improved Logging

## [1.0.2-limited-preview] - 2023-05-19
### Added
- [LOGGER] Update init logger : maintain consistncy with all security agents
- [INSTRUMENTATION] Support for Embedded Jetty 9 & 11
- Added low priority instrumentations, turned off by default.
- Set WS thread names to start with NR-CSEC-
- Migrated build & release pipeline to GHA
- Added instrumentation and unit test cases for SQL batch operations
- Low severity event filter cleanup with 30 min interval.
- Added unit test cases for following:
    - Servlet 2.4, 5.0, 6.0
- Applied instrumentation priority changes
- Scheduler for FileCleaner

### Fixed
- NPE fix in unit test of R2DBC
- Amazon DynamoDB unit test 
- Make Amazon dynamodb unit test aarch64 comaptible
- Change hash int to set in introspector API of instrumentation unit tests.
- NR-118286 : case 1 : snapshot dir should be created always inside logs of nr-security-home
- Compatibility fix for file-operation instrumentation modules unit test in linux env.
- Move File exist hook to low priority instrumentation module
- Skip hook processing on Servlet low priority instrumentations modules
- Skip hook processing on internal threads
- Changes for IAST data pull (on demand #CC request)
- Removal of tmp file created for IAST scanning.
- First HC to be sent after 30 sec of thread launch
- Removed @NewField from Nashorn Instrumentation with Transaction map logic to avoid OOM issue

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
