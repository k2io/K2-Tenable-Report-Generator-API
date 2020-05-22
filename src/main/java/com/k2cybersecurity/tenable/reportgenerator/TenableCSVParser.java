package com.k2cybersecurity.tenable.reportgenerator;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.tenable.models.TenablePluginOutput;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenableCSVParser {
	private static void parseTenableReport(String TENABLE_CSV_FILE_PATH, List<TenableReport> tenableReports) {
		TenableCSVParser tenableCsvParser = new TenableCSVParser();
		tenableCsvParser.parse(TENABLE_CSV_FILE_PATH, tenableReports);
		System.out.println("Tenable csv parsing completed");
	}

	public List<TenableReport> parse(String fileName, List<TenableReport> tenableReports) {
		System.out.println("Parsing Tenable csv report");
		try {
			Reader reader = Files.newBufferedReader(Paths.get(fileName));
			CSVParser csvParser = new CSVParser(reader,
					CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreHeaderCase().withTrim());
//			System.out.println(csvParser.getHeaderNames());
			for (CSVRecord csvRecord : csvParser) {
				TenableReport tenableReport = new TenableReport();
				tenableReport.setPluginID(csvRecord.get("Plugin ID"));
				tenableReport.setcVE(csvRecord.get("CVE"));
				tenableReport.setcVSS(csvRecord.get("CVSS"));
				tenableReport.setRisk(csvRecord.get("Risk"));
				tenableReport.setHost(csvRecord.get("Host"));
				tenableReport.setProtocol(csvRecord.get("Protocol"));
				tenableReport.setPort(csvRecord.get("Port"));
				tenableReport.setName(csvRecord.get("Name"));
				tenableReport.setSynopsis(csvRecord.get("Synopsis"));
				tenableReport.setDescription(csvRecord.get("Description"));
				tenableReport.setSolution(csvRecord.get("Solution"));
				tenableReport.setSeeAlso(csvRecord.get("See Also"));
				String pluginOutput = csvRecord.get("Plugin Output");
				tenableReport.setPluginOutput(pluginOutput);

				TenablePluginOutput tenablePluginOutput = new TenablePluginOutput();

				String[] lls = pluginOutput.split("[\\r\\n]+");
				List<String> lines = Arrays.asList(lls);

				if (StringUtils.contains(pluginOutput, "URL\n" + "-----")) {
					String url = lls[lines.indexOf("URL") + 2];
					tenablePluginOutput.setUrl(url);
				}
				if (StringUtils.contains(pluginOutput, "Detection Information")) {
					String det = StringUtils.join(lls, "\n", lines.indexOf("Detection Information") + 2,
							lines.indexOf("Proof"));
					Map<String, String> parameterMap = new HashMap<String, String>();
					String[] pairs = det.split("\n");
					for (int i = 0; i < pairs.length; i++) {
						String pair = pairs[i];
						String[] keyValue = pair.split(":");
						parameterMap.put(keyValue[0].trim(), keyValue[1].trim());
					}
					tenablePluginOutput.setDetectionInformation(parameterMap);
				}

				if (StringUtils.contains(pluginOutput, "Proof")) {
					String proof = StringUtils.join(lls, "\n", lines.indexOf("Proof") + 2, lines.indexOf("Request"));
					tenablePluginOutput.setProof(proof);
				}

				if (StringUtils.contains(pluginOutput, "Request")) {
					String request = StringUtils.join(lls, "\n", lines.indexOf("Request") + 2,
							lines.indexOf("Response"));
					tenablePluginOutput.setRequest(request);
				}

				if (StringUtils.contains(pluginOutput, "Response")) {
					String response = StringUtils.join(lls, "\n", lines.indexOf("Response") + 2, lines.size());
					tenablePluginOutput.setResponse(response);
				}
				tenableReport.setTenablePluginOutput(tenablePluginOutput);
				tenableReports.add(tenableReport);
			}

			csvParser.close();
			return tenableReports;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static void sortReport(List<TenableReport> tenableReports) {
		List<TenableReport> critical = new ArrayList<TenableReport>();
		List<TenableReport> high = new ArrayList<TenableReport>();
		List<TenableReport> medium = new ArrayList<TenableReport>();
		List<TenableReport> low = new ArrayList<TenableReport>();
		List<TenableReport> informational = new ArrayList<TenableReport>();
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "Critical")) {
				critical.add(tenableReport);
			} else if (StringUtils.equals(tenableReport.getRisk(), "High")) {
				high.add(tenableReport);
			} else if (StringUtils.equals(tenableReport.getRisk(), "Medium")) {
				medium.add(tenableReport);
			} else if (StringUtils.equals(tenableReport.getRisk(), "Low")) {
				low.add(tenableReport);
			} else if (StringUtils.equals(tenableReport.getRisk(), "Informational")) {
				informational.add(tenableReport);
			}
		}
		tenableReports.clear();
		tenableReports.addAll(critical);
		tenableReports.addAll(high);
		tenableReports.addAll(medium);
		tenableReports.addAll(low);
		tenableReports.addAll(informational);
	}

	public static void run(List<TenableReport> tenableReports, String TENABLE_CSV_FILE_PATH) {

		parseTenableReport(TENABLE_CSV_FILE_PATH, tenableReports);

		sortReport(tenableReports);
	}

}
