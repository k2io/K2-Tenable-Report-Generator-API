package com.k2cybersecurity.reportgenerator;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.k2.reportgenerator.K2CSVParser;
import com.k2cybersecurity.tenable.reportgenerator.TenableCSVParser;

public class Runner {

	public static void main(String[] args) {
		System.out.println("Hello Prateek! Your new project Report generator");
		System.out.println("K2 Report : " + args[1]);
		System.out.println("Tenable Report : " + args[2]);

//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_04282020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-2.csv";

//		String K2_CSV_FILE_PATH = "/Users/prateek/Downloads/Attacks_CSV_05062020.csv";
//		String TENABLE_CSV_FILE_PATH = "/Users/prateek/Downloads/prateek_dvja-5.csv";

		String REPORT_NAME = args[0];
		String K2_CSV_FILE_PATH = args[1];
		String TENABLE_CSV_FILE_PATH = args[2];
		String OUTPUT_DIR = args[3];

		List<K2Report> k2Reports = new ArrayList<K2Report>();
		K2CSVParser.run(K2_CSV_FILE_PATH, k2Reports);

		if (StringUtils.equalsIgnoreCase(REPORT_NAME, "tenable")) {
			TenableCSVParser.run(TENABLE_CSV_FILE_PATH, k2Reports, OUTPUT_DIR);
		} else {
			System.out.println("Only Tenable is supported now");
		}
	}
}
