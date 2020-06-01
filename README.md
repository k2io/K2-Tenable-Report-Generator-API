# K2-Report-Generator-API

This repository contains code to merge vulnerability scan report produced by DAST solution (e.g. Tenable) with the results K2 generates during those scans.

The executable JAR package will produce combined report.

This is an executable JAR package. 

Build Jar using command:

```
mvn clean package
```

Use Case:

```
java -jar k2-report-generator-api.jar -dast "<vendor-name>" -outputDir "<output-dir-path-where-reports-will-extract>" -dastProperties "<path-to-dast-properties-file>" -k2Properties "<path-to-k2-properties-file>" -scanId "<scan-id>" -hostIp "<hostip>" -appName "<web-application-name>"
```
