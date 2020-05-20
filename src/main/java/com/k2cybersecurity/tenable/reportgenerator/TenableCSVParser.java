package com.k2cybersecurity.tenable.reportgenerator;

import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.k2cybersecurity.k2.models.K2MinifiedOutput;
import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.reportgenerator.CSVWriter;
import com.k2cybersecurity.tenable.models.BriefReport;
import com.k2cybersecurity.tenable.models.CombinedMapValue;
import com.k2cybersecurity.tenable.models.ModifiedK2Report;
import com.k2cybersecurity.tenable.models.TenableFinalReport;
import com.k2cybersecurity.tenable.models.TenablePluginOutput;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenableCSVParser {
	private static int tenableCount;
	private static int tenableInformationCount;
	private static int tenableLowCount;
	private static int tenableMediumCount;
	private static int tenableHighCount;
	private static int tenableCriticalCount;
	private static int k2HighCount;
	private static int totalCount;
	private static int commonFindCount;
	private static int onlyK2FindCount;
	private static int onlyTenableFindCount;
	private static Set<String> urls = new HashSet<String>();
	private static Map<String, Integer> summaryMap = new HashMap<String, Integer>();
	private static Map<String, Integer> sumMap = new HashMap<String, Integer>();
	private static List<TenableFinalReport> tenableFinalReports = new ArrayList<TenableFinalReport>();

	private static Map<ImmutablePair<String, String>, List<ModifiedK2Report>> onlyK2Detect = new HashMap<ImmutablePair<String, String>, List<ModifiedK2Report>>();

	private static Map<ImmutablePair<String, String>, CombinedMapValue> endReport = new HashMap<ImmutablePair<String, String>, CombinedMapValue>();
	private static Map<String, List<String>> vulApis = new HashMap<String, List<String>>();

	public List<TenableReport> parse(String fileName, List<TenableReport> tenableReports) {
		System.out.println("In Tenable parse method");
		try {
			Reader reader = Files.newBufferedReader(Paths.get(fileName));
			CSVParser csvParser = new CSVParser(reader,
					CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreHeaderCase().withTrim());
			System.out.println(csvParser.getHeaderNames());
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

	private static void parseTenableReport(String TENABLE_CSV_FILE_PATH, List<TenableReport> tenableReports) {
		TenableCSVParser tenableCsvParser = new TenableCSVParser();
		tenableCsvParser.parse(TENABLE_CSV_FILE_PATH, tenableReports);
		System.out.println("after Tenable csv parsing");
	}

	private static void mergeTenableReports(List<TenableReport> tenableReports, List<ModifiedK2Report> k2Reports) {

		for (TenableReport tenableReport : tenableReports) {
			TenableFinalReport tenableFinalReport = new TenableFinalReport();
			tenableFinalReport.setTenableReport(tenableReport);

			String url = null;
			String inputName = null;
			String injectedPayload = null;
			if (tenableReport.getTenablePluginOutput().getUrl() != null) {
				url = tenableReport.getTenablePluginOutput().getUrl();
			}
			if (tenableReport.getTenablePluginOutput().getDetectionInformation() != null) {
				inputName = tenableReport.getTenablePluginOutput().getDetectionInformation().get("Input Name");
			}
			if (tenableReport.getTenablePluginOutput().getDetectionInformation() != null) {
				injectedPayload = tenableReport.getTenablePluginOutput().getDetectionInformation()
						.get("Injected Payload");
			}

			List<K2MinifiedOutput> k2output1 = new ArrayList<K2MinifiedOutput>();
			List<K2MinifiedOutput> k2output2 = new ArrayList<K2MinifiedOutput>();
			String finalK2Output = "";

			for (ModifiedK2Report k2Report : k2Reports) {
				K2MinifiedOutput k2MinifiedOutput = new K2MinifiedOutput();

				if (StringUtils.isNotEmpty(url) && StringUtils.endsWith(url, k2Report.gethTTPURL())) {
					if (StringUtils.contains(tenableReport.getName(), "SQL Injection")
							&& StringUtils.equals(k2Report.getAttackDescription(), "SQL Injection Attack")) {
						k2MinifiedOutput.sethTTPURL(k2Report.gethTTPURL());
						k2MinifiedOutput.setAttackDescription(k2Report.getAttackDescription());
						k2MinifiedOutput.setFileName(k2Report.getFileName());
						k2MinifiedOutput.setMethodName(k2Report.getMethodName());
						k2MinifiedOutput.setLineNumber(k2Report.getLineNumber());
						k2MinifiedOutput.setParameterMap(k2Report.getParameterMap());
						k2MinifiedOutput.setExecutedQueryOrCommand(k2Report.getExecutedQueryOrCommand());
						k2Report.setFoundByTenable(true);
						if (StringUtils.isNotEmpty(inputName) && StringUtils.isNotEmpty(injectedPayload)
								&& k2Report.getParameterMap().contains(inputName)
								&& k2Report.getParameterMap().contains(injectedPayload)) {
							k2output1.add(k2MinifiedOutput);
						} else {
							k2output2.add(k2MinifiedOutput);
						}
					} else if (StringUtils.contains(tenableReport.getName(), "Cross-Site Scripting (XSS)")
							&& StringUtils.contains(k2Report.getAttackDescription(), "XSS Attack")) {
						k2MinifiedOutput.sethTTPURL(k2Report.gethTTPURL());
						k2MinifiedOutput.setAttackDescription(k2Report.getAttackDescription());
						k2MinifiedOutput.setFileName(k2Report.getFileName());
						k2MinifiedOutput.setMethodName(k2Report.getMethodName());
						k2MinifiedOutput.setLineNumber(k2Report.getLineNumber());
						k2MinifiedOutput.setParameterMap(k2Report.getParameterMap());
						k2MinifiedOutput.setExecutedQueryOrCommand(k2Report.getExecutedQueryOrCommand());
						k2Report.setFoundByTenable(true);
						if (StringUtils.isNotEmpty(inputName) && StringUtils.isNotEmpty(injectedPayload)
								&& k2Report.getParameterMap().contains(inputName)
								&& k2Report.getParameterMap().contains(injectedPayload)) {
							k2output1.add(k2MinifiedOutput);
						} else {
							k2output2.add(k2MinifiedOutput);
						}
					}

				}
			}
			if (k2output1.size() > 0) {
				tenableFinalReport.setBothDetected(k2output1);
				finalK2Output += "K2 has also detected the same vulnerability with following additional details.\n";
				for (K2MinifiedOutput output : k2output1) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (k2output2.size() > 0) {
				tenableFinalReport.setAdditionalFindings(k2output2);
				finalK2Output += "K2 has found the following additional attacks for this URL\n";
				for (K2MinifiedOutput output : k2output2) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (StringUtils.isEmpty(finalK2Output)) {
				tenableFinalReport.setBothDetected(new ArrayList<K2MinifiedOutput>());
				tenableFinalReport.setAdditionalFindings(new ArrayList<K2MinifiedOutput>());
				String msg = "K2 has not found any attack for this URL.";
				finalK2Output += msg;
			}

			System.out.println("finalK2Output : " + finalK2Output);
			tenableReport.setK2output(finalK2Output);
			tenableFinalReports.add(tenableFinalReport);

		}
	}

	private static void prepareAttacksFoundByOnlyK2(List<ModifiedK2Report> modifiedK2Reports) {
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			if (!modifiedK2Report.isFoundByTenable()) {
				ImmutablePair<String, String> pair = new ImmutablePair<String, String>(
						modifiedK2Report.getAttackDescription(), modifiedK2Report.gethTTPURL());
				List<ModifiedK2Report> list = onlyK2Detect.get(pair);
				if (list == null || list.size() == 0) {
					list = new ArrayList<ModifiedK2Report>();
					list.add(modifiedK2Report);
				} else {
					list.add(modifiedK2Report);
				}
				onlyK2Detect.put(pair, list);
			}
		}
	}

	private static void addAttacksFoundByOnlyK2InCSV(List<TenableReport> tenableReports,
			List<ModifiedK2Report> modifiedK2Reports) {
		int counter = 0;
		for (Pair<String, String> pair : onlyK2Detect.keySet()) {
			List<ModifiedK2Report> list = onlyK2Detect.get(pair);

			String finalMessage = "Tenable did not detect this vulnerability.\n\n";
			TenableReport tr = new TenableReport();
			tr.setPluginID("K2");
			tr.setcVSS("7.5");
			tr.setRisk("High");
			tr.setHost(list.get(0).getiP());
			tr.setProtocol("TCP");
			tr.setPort(StringUtils.split(list.get(0).getPorts(), ',')[0]);
			tr.setName(pair.getLeft());
			tr.setSynopsis(pair.getLeft());

			String k2Report = "";
			k2Report += "Vulnerability : " + pair.getLeft();
			k2Report += "\nPath : " + pair.getRight();
			k2Report += "\nFinding ID: " + list.get(0).getIncidentID();
			k2Report += "\nRisk : High";
			k2Report += "\nFile Name : " + list.get(0).getFileName();
			k2Report += "\nMethod Name : " + list.get(0).getMethodName();
			k2Report += "\nLine Number : " + list.get(0).getLineNumber();
			k2Report += "\nParameters : ";
			for (ModifiedK2Report modifiedK2Report : list) {
				k2Report += "\n" + modifiedK2Report.getParameterMap();
			}
			tr.setK2output(finalMessage + k2Report);
			tenableReports.add(counter++, tr);
		}
	}

	private static void printMergedTenableReport(List<TenableReport> tenableReports) {
		for (TenableReport tenableReport : tenableReports) {
			printTenableData(tenableReport);
			System.out.println(tenableReport.getK2output());
		}
	}

	private static void printTenableData(TenableReport tenableReport) {
		System.out.println("Tenable Data: ");
//		System.out.println("URL: " + tenableReport.getTenablePluginOutput().getUrl());
//		System.out.println("Name: " + tenableReport.getName());
		System.out.println("Detection Information: " + tenableReport.toString());
	}

	private static void addSummaryInFinalReport(List<TenableReport> tenableReports, List<BriefReport> briefReports) {
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "Informational")) {
				tenableInformationCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Low")) {
				tenableLowCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Medium")) {
				tenableMediumCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Critical")) {
				tenableCriticalCount++;
			} else if (!StringUtils.equals(tenableReport.getPluginID(), "K2")
					&& StringUtils.equals(tenableReport.getRisk(), "High")) {
				tenableHighCount++;
			}
		}

		tenableCount = tenableInformationCount + tenableLowCount + tenableMediumCount + tenableHighCount
				+ tenableCriticalCount;

		summaryMap.put("tenableInformationCount", tenableInformationCount);
		summaryMap.put("tenableLowCount", tenableLowCount);
		summaryMap.put("tenableMediumCount", tenableMediumCount);
		summaryMap.put("tenableHighCount", tenableHighCount);
		summaryMap.put("tenableCriticalCount", tenableCriticalCount);
		summaryMap.put("tenableCount", tenableCount);

		for (BriefReport briefReport : briefReports) {
			k2HighCount += briefReport.getK2ReportedAttacks().size();

			int t = briefReport.getTenableReportedAttacks().size();
			int k = briefReport.getK2ReportedAttacks().size();
			if (t >= k) {
				totalCount += t;
			} else {
				totalCount += k;
			}

			if (briefReport.isDetctedByK2() && !briefReport.isDetctedByTenable()) {
				onlyK2FindCount += briefReport.getK2ReportedAttacks().size();
			}
			if (briefReport.isDetctedByTenable() && !briefReport.isDetctedByK2()) {
				onlyTenableFindCount += briefReport.getTenableReportedAttacks().size();
			}
			if (briefReport.isDetctedByTenable() && briefReport.isDetctedByK2()) {
				if (t < k) {
					commonFindCount += briefReport.getTenableReportedAttacks().size();
					onlyK2FindCount += k - t;
				} else {
					commonFindCount += briefReport.getK2ReportedAttacks().size();
					onlyTenableFindCount += t - k;
				}
			}
		}
		summaryMap.put("k2HighCount", k2HighCount);

		summaryMap.put("totalCount", totalCount);
		summaryMap.put("commonFindCount", commonFindCount);
		summaryMap.put("onlyK2FindCount", onlyK2FindCount);
		summaryMap.put("onlyTenableFindCount", onlyTenableFindCount);

		String finalMessage = "Summary\n=========\n\nTenable:\nTotal Vulnerabilities = " + tenableCount
				+ "\nInformational Vulnerabilities = " + tenableInformationCount + "\nLow Risk Vulnerabilities = "
				+ tenableLowCount + "\nMedium Risk Vulnerabilities = " + tenableMediumCount
				+ "\nHigh Risk Vulnerabilities = " + tenableHighCount + "\nCritical Risk Vulnerabilities = "
				+ tenableCriticalCount + "\n\nK2:\n" + "High Risk Vulnerabilities = " + k2HighCount
				+ "\n\nComparison:\n Total High Risk Vulnerabilities = " + totalCount
				+ "\nHigh Risk Vulnerabilities (Both K2 and Tenable has found) = " + commonFindCount
				+ "\nHigh Risk Vulnerabilities (Found by Tenable Only) = " + onlyTenableFindCount
				+ "\nHigh Risk Vulnerabilities (Found by K2 Only) = " + onlyK2FindCount;

		TenableReport tr = new TenableReport();
		tr.setPluginID("Summary");
		tr.setDescription(finalMessage);
		tenableReports.add(0, tr);
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

	private static void createBriefReport(List<TenableReport> tenableReports, List<ModifiedK2Report> modifiedK2Reports,
			List<BriefReport> briefReports) {
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			urls.add(modifiedK2Report.gethTTPURL());
		}
		for (TenableReport tenableReport : tenableReports) {
			if (tenableReport.getTenablePluginOutput() != null
					&& StringUtils.isNotBlank(tenableReport.getTenablePluginOutput().getUrl())) {
				String url = tenableReport.getTenablePluginOutput().getUrl();
				urls.add("/" + StringUtils.split(url, '/')[2]);
			}
		}

		for (String str : urls) {
			BriefReport briefReport = new BriefReport();
			briefReport.setUrl(str);
			for (TenableReport tenableReport : tenableReports) {
				if (tenableReport.getTenablePluginOutput() != null
						&& tenableReport.getTenablePluginOutput().getUrl() != null
						&& StringUtils.endsWith(tenableReport.getTenablePluginOutput().getUrl(), str)) {
					briefReport.getTenableReportedAttacks().add(tenableReport.getName());
				}
			}
			if (briefReport.getTenableReportedAttacks().size() > 0) {
				briefReport.setDetctedByTenable(true);
			}

			for (ModifiedK2Report k2Report : modifiedK2Reports) {
				if (StringUtils.equals(k2Report.gethTTPURL(), str)) {
					briefReport.getK2ReportedAttacks().add(k2Report.getAttackDescription());
				}
			}
			if (briefReport.getK2ReportedAttacks().size() > 0) {
				briefReport.setDetctedByK2(true);
			}
			briefReports.add(briefReport);
		}

	}

	public static void run(String TENABLE_CSV_FILE_PATH, List<K2Report> k2Reports) {
		List<TenableReport> tenableReports = new ArrayList<TenableReport>();
		List<ModifiedK2Report> modifiedK2Reports = new ArrayList<ModifiedK2Report>();
		List<BriefReport> briefReports = new ArrayList<BriefReport>();

		try {
			for (K2Report k2Report : k2Reports) {
				ModifiedK2Report temp = new ModifiedK2Report();
				BeanUtils.copyProperties(temp, k2Report);
				modifiedK2Reports.add(temp);
			}
		} catch (IllegalAccessException | InvocationTargetException e) {
			System.out.println("Exception in bean copy : " + e);
		}
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			System.out.println("Prateek \n\n\n" + modifiedK2Report);
		}
		parseTenableReport(TENABLE_CSV_FILE_PATH, tenableReports);

		sortReport(tenableReports);

		prepareEndReport(tenableReports, k2Reports);

		combineEndReport(endReport);

		printEndReport(endReport);

		mergeTenableReports(tenableReports, modifiedK2Reports);

		prepareAttacksFoundByOnlyK2(modifiedK2Reports);

		addAttacksFoundByOnlyK2InCSV(tenableReports, modifiedK2Reports);

		createBriefReport(tenableReports, modifiedK2Reports, briefReports);

		addSummaryInFinalReport(tenableReports, briefReports);

		CSVWriter.writeMergedReport(tenableReports);
		CSVWriter.writeBriefReport(briefReports);

		prepareSummary(endReport);
		prepareVulnerableApis(endReport);
		TenablePDFWriter.write(sumMap, vulApis, endReport);

		TenablePDFWriter.writeOld(summaryMap, onlyK2Detect, tenableFinalReports);
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
						System.out
								.println("HELLO ===> " + immutablePair.toString() + " - " + immutablePair2.toString());
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Reflected XSS Attack")
							&& !StringUtils.equals(immutablePair2.getRight(), "Reflected XSS Attack") && StringUtils
									.containsIgnoreCase(immutablePair2.getRight(), "Cross-Site Scripting (XSS)")) {
						System.out
								.println("HELLO ===> " + immutablePair.toString() + " - " + immutablePair2.toString());
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					} else if (StringUtils.equals(immutablePair.getRight(), "Remote Code Execution")
							&& !StringUtils.equals(immutablePair2.getRight(), "Remote Code Execution")
							&& StringUtils.containsIgnoreCase(immutablePair2.getRight(),
									"Operating System Command Injection")) {
						System.out
								.println("HELLO ===> " + immutablePair.toString() + " - " + immutablePair2.toString());
						toDelete.add(immutablePair2);
						endReport.get(immutablePair).getTenableReports()
								.addAll(endReport.get(immutablePair2).getTenableReports());
					}
				}
			}
		}

		for (ImmutablePair<String, String> immutablePair : toDelete) {
			System.out.println("Deleting ===== " + immutablePair.getLeft() + " - " + immutablePair.getRight());
			endReport.remove(immutablePair);
		}
	}

	private static void prepareSummary(Map<ImmutablePair<String, String>, CombinedMapValue> endReport) {

//		summaryMap.put("tenableInformationCount", tenableInformationCount);
//		summaryMap.put("tenableLowCount", tenableLowCount);
//		summaryMap.put("tenableMediumCount", tenableMediumCount);
//		summaryMap.put("tenableHighCount", tenableHighCount);
//		summaryMap.put("tenableCriticalCount", tenableCriticalCount);
//		summaryMap.put("tenableCount", tenableCount);
//		summaryMap.put("k2HighCount", k2HighCount);

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
		System.out.println("\n\n\nPRINTING END REPORT");
		for (ImmutablePair<String, String> pair : endReport.keySet()) {
			System.out.println(pair.getLeft() + " : " + pair.getRight());
		}
		System.out.println("=== ENDING ===\n\n\n");
	}

}
