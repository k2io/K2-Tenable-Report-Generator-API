package com.k2cybersecurity.tenable.reportgenerator;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.tenable.models.CombinedMapValue;
import com.k2cybersecurity.tenable.models.TenablePluginOutput;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenableCSVParser {
	private static Map<String, Integer> sumMap = new HashMap<String, Integer>();
	private static Map<ImmutablePair<String, String>, CombinedMapValue> endReport = new HashMap<ImmutablePair<String, String>, CombinedMapValue>();
	private static Map<String, List<String>> vulApis = new HashMap<String, List<String>>();

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
//		tenableReports.addAll(medium);
//		tenableReports.addAll(low);
//		tenableReports.addAll(informational);
	}

	private static void prepareEndReport(List<TenableReport> tenableReports, List<K2Report> k2Reports) {
		for (TenableReport tenableReport : tenableReports) {
			String url = null;
			String uri = null;
			if (tenableReport.getTenablePluginOutput().getUrl() != null) {
				url = tenableReport.getTenablePluginOutput().getUrl();
				uri = StringUtils.substring(url, StringUtils.ordinalIndexOf(url, "/", 3));
			}
			ImmutablePair<String, String> pair = new ImmutablePair<String, String>(uri, tenableReport.getName());

			if (endReport.containsKey(pair)) {
				CombinedMapValue combinedMapValue = endReport.get(pair);
				if (combinedMapValue.getTenableReports().size() > 0) {
					combinedMapValue.getTenableReports().add(tenableReport);
				} else {
					combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				}
			} else {
				CombinedMapValue combinedMapValue = new CombinedMapValue();
				combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				combinedMapValue.getTenableReports().add(tenableReport);
				combinedMapValue.setK2Reports(new ArrayList<K2Report>());
				endReport.put(pair, combinedMapValue);
			}

		}
		for (K2Report k2Report : k2Reports) {
			ImmutablePair<String, String> pair = new ImmutablePair<String, String>(k2Report.gethTTPURL(),
					k2Report.getAttackDescription());
			if (endReport.containsKey(pair)) {
				CombinedMapValue combinedMapValue = endReport.get(pair);
				if (combinedMapValue.getK2Reports().size() > 0) {
					combinedMapValue.getK2Reports().add(k2Report);
				} else {
					combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				}
			} else {
				CombinedMapValue combinedMapValue = new CombinedMapValue();
				combinedMapValue.setTenableReports(new ArrayList<TenableReport>());
				combinedMapValue.setK2Reports(new ArrayList<K2Report>());
				combinedMapValue.getK2Reports().add(k2Report);
				endReport.put(pair, combinedMapValue);
			}

		}
	}

	private static void combineEndReport(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {

		Set<ImmutablePair<String, String>> set = endReport.keySet();
		Set<ImmutablePair<String, String>> toDelete = new HashSet<ImmutablePair<String, String>>();

		for (ImmutablePair<String, String> immutablePair : set) {
			for (ImmutablePair<String, String> immutablePair2 : set) {
				if (StringUtils.equals(immutablePair.getLeft(), immutablePair2.getLeft())) {
					if (StringUtils.equals(immutablePair.getRight(), "SQL Injection Attack")
							&& !StringUtils.equals(immutablePair2.getRight(), "SQL Injection Attack")
							&& StringUtils.containsIgnoreCase(immutablePair2.getRight(), "SQL Injection")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Reflected XSS Attack")
							&& !StringUtils.equals(immutablePair2.getRight(), "Reflected XSS Attack") && StringUtils
									.containsIgnoreCase(immutablePair2.getRight(), "Cross-Site Scripting (XSS)")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Remote Code Execution")
							&& !StringUtils.equals(immutablePair2.getRight(), "Remote Code Execution")
							&& StringUtils.containsIgnoreCase(immutablePair2.getRight(),
									"Operating System Command Injection")) {
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					}
				}
			}
		}

		for (ImmutablePair<String, String> immutablePair : toDelete) {
			endReport.remove(immutablePair);
		}
	}

	private static void prepareSummary(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {

		sumMap.put("totalCount", endReport.size());
		int commonFindCount = 0;
		int onlyK2Count = 0;
		int onlyTenableCount = 0;

		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			if (endReport.get(pair).getK2Reports().size() > 0 && endReport.get(pair).getTenableReports().size() > 0) {
				commonFindCount++;
			} else if (endReport.get(pair).getK2Reports().size() > 0
					&& endReport.get(pair).getTenableReports().size() == 0) {
				onlyK2Count++;
			} else if (endReport.get(pair).getTenableReports().size() > 0
					&& endReport.get(pair).getK2Reports().size() == 0) {
				onlyTenableCount++;
			}
		}
		sumMap.put("commonFindCount", commonFindCount);
		sumMap.put("onlyK2FindCount", onlyK2Count);
		sumMap.put("onlyTenableFindCount", onlyTenableCount);

	}

	private static void prepareVulnerableApis(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {
		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			if (vulApis.containsKey(pair.getLeft())) {
				vulApis.get(pair.getLeft()).add(pair.getRight());
			} else {
				vulApis.put(pair.getLeft(), new ArrayList<String>());
				vulApis.get(pair.getLeft()).add(pair.getRight());
			}
		}
	}

	private static void printEndReport(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {
		System.out.println("\nPRINTING VULNERABILITIES");
		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			System.out.println(pair.getLeft() + " : " + pair.getRight());
		}
		System.out.println("======\n");
	}

	public static void run(String TENABLE_CSV_FILE_PATH, List<K2Report> k2Reports, String OUTPUT_DIR) {
		List<TenableReport> tenableReports = new ArrayList<TenableReport>();

		parseTenableReport(TENABLE_CSV_FILE_PATH, tenableReports);

		sortReport(tenableReports);

		prepareEndReport(tenableReports, k2Reports);

		combineEndReport(endReport);

		printEndReport(endReport);

		prepareSummary(endReport);

		prepareVulnerableApis(endReport);

		TenablePDFWriter.write(sumMap, vulApis, endReport, OUTPUT_DIR);
	}

}
