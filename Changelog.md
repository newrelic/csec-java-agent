# Changelog
Noteworthy changes to the agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.9-public-preview] - TO BE DECIDED
### Changes
- gRPC client v1.4.0+ Support: The security agent now supports gRPC client version 1.4.0 and above (with protobuf-java-utils version 3.0.0 and above)
- gRPC server v1.4.0+ Support: The security agent now supports gRPC server version 1.4.0 and above (with protobuf-java-utils version 3.0.0 and above)
- Add a Logger and Cloud Reporting API for instrumentation modules
- Glassfish Support: The security agent now also supports Glassfish server
- FileIntegrity is marked if any of following is changed - existence, length, permissions, last modified
- Drop RXSS events on the basis of Content-Type Exclusion List
- Akka server v10.0+ Support: The security agent now supports Akka server version 10.0 and above (with scala 2.11 and above)
- Separate out File.exists instrumentation from low-priority instrumentation module
- Removed Schema validation dependency everit-json-schema:1.14.2
- Introduced new dependency commons-collections4:4.4

### Fixes
- NR-212335 : support lower case stdout for log_file_name
- NR-215332 : Add java working temp directory to server info for exclusion
- NR-216474 : fix for Null Pointer exception for FILE_OPERATION
- NR-216456 : Fix for Class Cast Exception
- NR-215452 : Added the CC#_id to the completed list empty if absent in case of 2xx or 4xx response

## [1.0.8-public-preview] - 2024-1-11
### Changes
- Support for stored procedure call detection in SQL events
- Support for extracting environment variables in case of Remote Code Execution events
- Support for executing script file analysis in case of Remote Code Execution events
- Enabled the transformation of the low-priority instrumentation module by default in case of IAST
- SecureCookie schema check has been removed

### Fixes
- Incorrect user file details in the vulnerability details
- Low severity hook event was not generated when the same url can process multiple request methods
- Detection of server app directory to mitigate false positives for File Access vulnerability

## [1.0.7-public-preview] - 2023-12-6
### Changes
- Async HttpClient v2+ Support: The security agent now also supports Async HTTP client version 2 and above
- Sun Net HTTP Server support: The security agent now supports Sun Net HTTP Server
- Add APM trace information population in the event
- WS headers added : NR-CSEC-ENTITY-GUID & NR-CSEC-ENTITY-NAME
- JSON version bump to 1.1.1
- Add critical error logging via LogMessage event
### Fixes
- Insecure cookie attack vulnerability was flagged in secure communication, accounting communication type to mitigate the issue
- DynamoDB v2 issue: missing attribute values for conditionCheck method in case of transactWriteItems operation on DynamoDB
- Never print LicenseKey 
### Misc
- Updated unit test cases for all the outbound request instrumentation modules to include test cases for csec parent id header
- Unit test cases for Async HttpClient v2+
- Unit test cases for Jetty v12+
- Unit test cases for Sun Net HTTP Server
- Unit test cases for Netty Server

## [1.0.6-public-preview] - 2023-10-17
### Changes
- Cassandra DB v3.0+ Support: The Security agent now supports Cassandra DB version 3.0 and above
- HttpClient v5.0+ Support: The Security agent now also supports HttpClient version 5.0 and above
- Support for std-out logging
- Added feature for Daily log rollover
- Support for logger config: log_file_count and log_limit_in_kbytes
- Relocating all our instrumentation packages under the package com.newrelic.agent.security.instrumentation.*
- Package Refactoring for Unit Tests: Move packaging for all UTs to com.nr.agent.security.instrumentation.*
- Set default value for low severity instrumentation to false

### Fixes
- Fixed ClassNotFoundException for IOStreamHelper class with Glassfish
- Updated PostgreSQL UTs with Embedded Server instead of test container

## [1.0.5-public-preview] - 2023-08-29
### Changes
- [INSTRUMENTATION] Support for Apache log4j 3.0.0-alpha1 (new version released on 21 June 2023)
- [INSTRUMENTATION] Support for Commons.jxpath
- Randomization in WS connection delay
- [FIX] Issue with HealthChecking having empty process stats issue
- Add agent monitoring details and matrix to health check
- Limiting the supported version range for Jetty, due to the new version release of Jetty on 7th Aug, 2023

## [1.0.4-public-preview] - 2023-06-20
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
