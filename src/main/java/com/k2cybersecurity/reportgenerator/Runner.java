package com.k2cybersecurity.reportgenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.k2.reportgenerator.K2CSVParser;
import com.k2cybersecurity.tenable.models.TenableReport;
import com.k2cybersecurity.tenable.reportgenerator.GetScannedReports;
import com.k2cybersecurity.tenable.reportgenerator.TenableCSVGenerator;
import com.k2cybersecurity.tenable.reportgenerator.TenableCSVParser;
import com.k2cybersecurity.tenable.reportgenerator.TenablePdfGenerator;

public class Runner {
	private static String dast = StringUtils.EMPTY;
	private static String dastProperties = StringUtils.EMPTY;
	private static String k2Properties = StringUtils.EMPTY;
	private static String outputDir = StringUtils.EMPTY;
	private static String scanId = StringUtils.EMPTY;
	private static String appName = StringUtils.EMPTY;
	private static String hostIp = StringUtils.EMPTY;
	private static String k2ReportName = StringUtils.EMPTY;
	private static String tenableReportName = StringUtils.EMPTY;

	public static void main(String[] args) {
		extractParams(args);
		withApi(args);
//		withoutApi(args);
	}

	private static void extractParams(String[] args) {
		for (int i = 0; i < args.length; i++) {
			if (StringUtils.startsWith(args[i], "-")) {
				if (StringUtils.equals(args[i], "-dast")) {
					dast = args[++i];
				} else if (StringUtils.equals(args[i], "-dastProperties")) {
					dastProperties = args[++i];
				} else if (StringUtils.equals(args[i], "-k2Properties")) {
					k2Properties = args[++i];
				} else if (StringUtils.equals(args[i], "-outputDir")) {
					outputDir = args[++i];
				} else if (StringUtils.equals(args[i], "-scanId")) {
					scanId = args[++i];
				} else if (StringUtils.equals(args[i], "-appName")) {
					appName = args[++i];
				} else if (StringUtils.equals(args[i], "-hostIp")) {
					hostIp = args[++i];
				} else if (StringUtils.equals(args[i], "-k2ReportName")) {
					k2ReportName = args[++i];
				} else if (StringUtils.equals(args[i], "-tenableReportName")) {
					tenableReportName = args[++i];
				}
			}
		}
	}

	private static void withoutApi(String[] args) {
		if (StringUtils.isBlank(dast)) {
			System.out.println("Please provide -dast parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(k2ReportName)) {
			System.out.println("Please provide -k2ReportName parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(tenableReportName)) {
			System.out.println("Please provide -tenableReportName parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(outputDir)) {
			System.out.println("Please provide -outputDir parameter");
			System.exit(1);
		}
		System.out.println("Printing user parameters:");
		System.out.println("dast : " + dast);
		System.out.println("k2ReportName : " + k2ReportName);
		System.out.println("k2TenableName : " + tenableReportName);
		System.out.println("outputDir : " + outputDir);
//	String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_04282020.csv";
//	String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-2.csv";

//	String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_05062020.csv";
//	String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-5.csv";

		String REPORT_NAME = dast;
		String K2_CSV_FILE_PATH = k2ReportName;
		String TENABLE_CSV_FILE_PATH = tenableReportName;
		String OUTPUT_DIR = outputDir;

		List<K2Report> k2Reports = new ArrayList<K2Report>();
		K2CSVParser.run(K2_CSV_FILE_PATH, k2Reports);

		if (StringUtils.equalsIgnoreCase(REPORT_NAME, "tenable")) {
			List<TenableReport> tenableReports = new ArrayList<TenableReport>();
			TenableCSVParser.run(tenableReports, TENABLE_CSV_FILE_PATH);
			TenablePdfGenerator.run(tenableReports, k2Reports, OUTPUT_DIR);
			TenableCSVGenerator.run(tenableReports, k2Reports, OUTPUT_DIR);
		} else {
			System.out.println("Only Tenable is supported now");
		}
	}

	private static void withApi(String[] args) {
		if (StringUtils.isBlank(dast)) {
			System.out.println("Please provide -dast parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(dastProperties)) {
			System.out.println("Please provide -dastProperties parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(k2Properties)) {
			System.out.println("Please provide -k2Properties parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(scanId)) {
			System.out.println("Please provide -scanid parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(hostIp)) {
			System.out.println("Please provide -hostIp parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(appName)) {
			System.out.println("Please provide -appName parameter");
			System.exit(1);
		}
		if (StringUtils.isBlank(outputDir)) {
			System.out.println("Please provide -outputDir parameter");
			System.exit(1);
		}
		System.out.println("Printing user parameters:");
		System.out.println("dast : " + dast);
		System.out.println("dastProperties : " + dastProperties);
		System.out.println("k2Properties : " + k2Properties);
		System.out.println("scanId : " + scanId);
		System.out.println("hostIp : " + hostIp);
		System.out.println("appName : " + appName);
		System.out.println("outputDir : " + outputDir);
		try {
			System.out.println("Creating directory " + outputDir);
			Files.createDirectories(Paths.get(outputDir));
		} catch (IOException e) {
			System.out.println("Error in directory creation" + e.getMessage());
		}

//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_04282020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-2.csv";

//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_05062020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-5.csv";

		if (StringUtils.equalsIgnoreCase(dast, "tenable")) {
			GetScannedReports.run(dastProperties, k2Properties, scanId, hostIp, appName, outputDir);
		} else {
			System.out.println("Only Tenable is supported now.");
			System.exit(1);
		}

		List<K2Report> k2Reports = new ArrayList<K2Report>();
		K2CSVParser.run(outputDir + "/K2-Report.csv", k2Reports);

		if (StringUtils.equalsIgnoreCase(dast, "tenable")) {
			List<TenableReport> tenableReports = new ArrayList<TenableReport>();
			TenableCSVParser.run(tenableReports, outputDir + "/Tenable-Report.csv");
			TenablePdfGenerator.run(tenableReports, k2Reports, outputDir);
			TenableCSVGenerator.run(tenableReports, k2Reports, outputDir);
		} else {
			System.out.println("Only Tenable is supported now");
			System.exit(1);
		}
	}

}
