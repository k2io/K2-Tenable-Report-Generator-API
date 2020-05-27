# k2-report-generator
This repository contains source code to merge reports produced by multiple competitive companies with K2.

This is an executable JAR package. 

Build Jar using command:
```
mvn clean package
```
To run it, use the following command:

```
java -jar k2-report-generator.jar
```

Use Case:

```
java -jar k2-report-generator.jar tenable <tenable-scan-id> <outpur-dir>
```