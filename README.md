# k2-report-generator
This repository contains code to merge vulnerability scan report produced by  DAST solution (e.g. Tenable) with the results K2 generates during those scans.

The executable JAR package will produce combined report.

This is an executable JAR package. 

Build Jar using command:
```
mvn clean package
```

Use Case:

```
java -jar k2-report-generator.jar -ip <host IP> -appport -appname <application name> -vendor tenable -scanid <tenable-scan-id> -dir <outpur-dir>
```
