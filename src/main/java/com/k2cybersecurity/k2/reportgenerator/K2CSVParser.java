package com.k2cybersecurity.k2.reportgenerator;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import com.k2cybersecurity.k2.models.K2Report;

public class K2CSVParser {

	public List<K2Report> parse(String fileName, List<K2Report> k2Reports) {
		System.out.println("Parsing K2 csv report");
		try {
			Reader reader = Files.newBufferedReader(Paths.get(fileName));
			CSVParser csvParser = new CSVParser(reader,
					CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreHeaderCase().withTrim());
//			System.out.println("K2 CSV headers : \n" + csvParser.getHeaderNames());
			for (CSVRecord csvRecord : csvParser) {
				K2Report k2Report = new K2Report();
				k2Report.setAttackTime(csvRecord.get("Attack Time"));
				k2Report.setiP(csvRecord.get("IP"));
				k2Report.setAttackDescription(csvRecord.get("Attack Description"));
				k2Report.setIncidentID(csvRecord.get("Incident ID"));
				k2Report.setFileName(csvRecord.get("File Name"));
				k2Report.sethTTPMethod(csvRecord.get("Method"));
				k2Report.setMethodName(csvRecord.get("Method Name"));
				k2Report.setLineNumber(csvRecord.get("Line Number"));
				k2Report.setApplicationName(csvRecord.get("Application Name"));
				k2Report.setPorts(csvRecord.get("Ports"));
				k2Report.sethTTPURL(csvRecord.get("HTTP URL"));
				k2Report.setExecutedQueryOrCommand(csvRecord.get("Executed Query/Command"));
				k2Report.setParameterMap(csvRecord.get("Parameter Map"));
				k2Report.setCookie(csvRecord.get("Cookie"));
				k2Report.setSyscall(csvRecord.get("Syscall"));
				k2Report.setSyscallModule(csvRecord.get("Syscall Module"));
				k2Report.setZerodayApplication(csvRecord.get("Zeroday Application"));
				k2Reports.add(k2Report);
//				System.out.println(k2Report.toString());
			}

			csvParser.close();
			return k2Reports;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static void parseK2Report(String K2_CSV_FILE_PATH, List<K2Report> k2Reports) {
		K2CSVParser k2csvParser = new K2CSVParser();
		k2csvParser.parse(K2_CSV_FILE_PATH, k2Reports);
		System.out.println("K2 CSV parsing completed");
	}

	private static void printK2Data(K2Report k2Report) {
		System.out.println("K2 Data: ");
		System.out.println("URL:                  " + k2Report.gethTTPURL());
		System.out.println("Attack Type: " + k2Report.getAttackDescription());
		System.out.println("File Name: " + k2Report.getFileName());
		System.out.println("API Method Name: " + k2Report.getMethodName());
		System.out.println("API File Number: " + k2Report.getLineNumber());
	}

	public static void run(String K2_CSV_FILE_PATH, List<K2Report> k2Reports) {
		parseK2Report(K2_CSV_FILE_PATH, k2Reports);
	}
}
