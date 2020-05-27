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

	public static void main(String[] args) {
		System.out.println("Report Type : " + args[0]);
		System.out.println("Tenable Scan ID : " + args[1]);
		System.out.println("Output Directory : " + args[2]);
		try {
			System.out.println("Creating directory " + args[2]);
			Files.createDirectories(Paths.get(args[2]));
		} catch (IOException e) {
			e.printStackTrace();
		}
//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_04282020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-2.csv";

//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_05062020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-5.csv";

		String REPORT_NAME = args[0];
		String SCAN_ID = args[1];
		String OUTPUT_DIR = args[2];

		GetScannedReports.run(SCAN_ID, OUTPUT_DIR);

		List<K2Report> k2Reports = new ArrayList<K2Report>();
		K2CSVParser.run(OUTPUT_DIR + "/K2-Report.csv", k2Reports);

		if (StringUtils.equalsIgnoreCase(REPORT_NAME, "tenable")) {
			List<TenableReport> tenableReports = new ArrayList<TenableReport>();
			TenableCSVParser.run(tenableReports, OUTPUT_DIR + "/Tenable-Report.csv");
			TenablePdfGenerator.run(tenableReports, k2Reports, OUTPUT_DIR);
			TenableCSVGenerator.run(tenableReports, k2Reports, OUTPUT_DIR);
		} else {
			System.out.println("Only Tenable is supported now");
		}
	}
}
