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

import com.k2cybersecurity.k2.models.K2MinifiedOutput;
import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.reportgenerator.CSVWriter;
import com.k2cybersecurity.tenable.models.BriefReport;
import com.k2cybersecurity.tenable.models.ModifiedK2Report;
import com.k2cybersecurity.tenable.models.TenablePluginOutput;
import com.k2cybersecurity.tenable.models.TenableReport;
import com.sun.org.apache.bcel.internal.generic.NEWARRAY;

public class TenableCSVParser {
	private static int tenableCount;
	private static int tenableInformationCount;
	private static int tenableLowCount;
	private static int tenableMediumCount;
	private static int tenableHighCount;
	private static int k2HighCount;
	private static int commonFindCount;
	private static int onlyK2FindCount;
	private static Set<String> urls = new HashSet<String>();

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
//			if (StringUtils.equals(tenableReport.getRisk(), "High")) {
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
					if (StringUtils.equals(tenableReport.getName(), "SQL Injection")
							&& StringUtils.equals(k2Report.getAttackDescription(), "SQL Injection Attack")) {
						k2MinifiedOutput.sethTTPURL(k2Report.gethTTPURL());
						k2MinifiedOutput.setAttackDescription(k2Report.getAttackDescription());
						k2MinifiedOutput.setFileName(k2Report.getFileName());
						k2MinifiedOutput.setMethodName(k2Report.getMethodName());
						k2MinifiedOutput.setLineNumber(k2Report.getLineNumber());
						k2MinifiedOutput.setParameterMap(k2Report.getParameterMap());
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
				finalK2Output += "K2 has also detected the same vulnerability with following additional details.\n";
				for (K2MinifiedOutput output : k2output1) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (k2output2.size() > 0) {
				finalK2Output += "K2 has found the following additional attacks for this URL\n";
				for (K2MinifiedOutput output : k2output2) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (StringUtils.isEmpty(finalK2Output)) {
				String msg = "K2 has not found any attack for this URL.";
				finalK2Output += msg;
			} else {
				commonFindCount++;
			}

			System.out.println("finalK2Output : " + finalK2Output);
			tenableReport.setK2output(finalK2Output);
//			}

		}
	}

	private static void addAttacksFoundByOnlyK2(List<TenableReport> tenableReports,
			List<ModifiedK2Report> modifiedK2Reports) {
		int counter = 0;
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			if (!modifiedK2Report.isFoundByTenable()) {
				String finalMessage = "High risk vulnerability detected by K2. Tenable did not detect this vulnerability.\n\n";
				TenableReport tr = new TenableReport();
				tr.setPluginID("K2");
				tr.setcVSS("7.5");
				tr.setRisk("High");
				tr.setHost(modifiedK2Report.getiP());
				tr.setProtocol("TCP");
				tr.setPort(StringUtils.split(modifiedK2Report.getPorts(), ',')[0]);
				tr.setName(modifiedK2Report.getAttackDescription());
				tr.setSynopsis(modifiedK2Report.getAttackDescription());
				tr.setK2output(finalMessage + modifiedK2Report.toString());
				tenableReports.add(counter++, tr);
				onlyK2FindCount++;
			}
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

	private static void countSummary(List<TenableReport> tenableReports, List<ModifiedK2Report> modifiedK2Reports) {
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "Informational")) {
				tenableInformationCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Low")) {
				tenableLowCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "Medium")) {
				tenableMediumCount++;
			} else if (StringUtils.equals(tenableReport.getRisk(), "High")) {
				tenableHighCount++;
			}
		}

		tenableCount = tenableReports.size();
		k2HighCount = modifiedK2Reports.size();

	}

	private static void addSummaryInFinalReport(List<TenableReport> tenableReports) {
		String finalMessage = "Summary\n===================\n\nTenable Findings count:\nTotal Vulnerabilities Count = "
				+ tenableCount + "\nTotal Information Count = " + tenableInformationCount + "\nTotal Low Count = "
				+ tenableLowCount + "\nTotal Medium Count = " + tenableMediumCount + "\nTotal High Count = "
				+ tenableHighCount + "\n\nK2 Findings Count:\nTotal Attack Count = " + k2HighCount
				+ "\nTotal High Count = " + k2HighCount
				+ "\n\nComparison:\nTotal count of distinct URL with High Risk (Both K2 and Tenable has found) = "
				+ commonFindCount + "\nHigh Vulnerabilities Findings Count by Tenable only= " + tenableHighCount
				+ "\nHigh Severity Attack count by K2 Only = " + onlyK2FindCount;

		TenableReport tr = new TenableReport();
		tr.setPluginID("Summary");
		tr.setDescription(finalMessage);
		tenableReports.add(0, tr);
		onlyK2FindCount++;
	}

	private static void sortReport(List<TenableReport> tenableReports) {
		List<TenableReport> high = new ArrayList<TenableReport>();
		List<TenableReport> medium = new ArrayList<TenableReport>();
		List<TenableReport> low = new ArrayList<TenableReport>();
		List<TenableReport> informational = new ArrayList<TenableReport>();
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "High")) {
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
		tenableReports.addAll(high);
		tenableReports.addAll(medium);
		tenableReports.addAll(low);
		tenableReports.addAll(informational);
	}

	private static void createBriefReport(List<TenableReport> tenableReports, List<ModifiedK2Report> modifiedK2Reports,
			List<BriefReport> briefReports) {
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			urls.add(modifiedK2Report.gethTTPURL());
		}
		for (TenableReport tenableReport : tenableReports) {
			if (StringUtils.equals(tenableReport.getRisk(), "High")) {
				if (tenableReport.getTenablePluginOutput() != null
						&& StringUtils.isNotBlank(tenableReport.getTenablePluginOutput().getUrl())) {
					String url = tenableReport.getTenablePluginOutput().getUrl();
					urls.add("/" + StringUtils.split(url, '/')[2]);
				}
			}
		}

		for (String str : urls) {
			BriefReport briefReport = new BriefReport();
			briefReport.setUrl(str);
			for (TenableReport tenableReport : tenableReports) {
				if (StringUtils.equals(tenableReport.getRisk(), "High")) {
					if (tenableReport.getTenablePluginOutput() != null
							&& tenableReport.getTenablePluginOutput().getUrl() != null
							&& StringUtils.endsWith(tenableReport.getTenablePluginOutput().getUrl(), str)) {
						briefReport.getTenableReportedAttacks().add(tenableReport.getName());
					}
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

	private static void createCompareReport(List<TenableReport> tenableReports,
			List<ModifiedK2Report> modifiedK2Reports, List<BriefReport> compareReport) {
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			urls.add(modifiedK2Report.gethTTPURL());
		}
		for (TenableReport tenableReport : tenableReports) {
			if (tenableReport.getTenablePluginOutput() != null
					&& StringUtils.isNotBlank(tenableReport.getTenablePluginOutput().getUrl())) {
				String url = tenableReport.getTenablePluginOutput().getUrl();
				urls.add(StringUtils.substring(url, StringUtils.ordinalIndexOf(url, "/", 3)));
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
			compareReport.add(briefReport);
		}

	}

	public static void run(String TENABLE_CSV_FILE_PATH, List<K2Report> k2Reports) {
		List<TenableReport> tenableReports = new ArrayList<TenableReport>();
		List<ModifiedK2Report> modifiedK2Reports = new ArrayList<ModifiedK2Report>();
		List<BriefReport> briefReports = new ArrayList<BriefReport>();
		List<BriefReport> compareReport = new ArrayList<BriefReport>();

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

		mergeTenableReports(tenableReports, modifiedK2Reports);

		countSummary(tenableReports, modifiedK2Reports);

		addAttacksFoundByOnlyK2(tenableReports, modifiedK2Reports);

		addSummaryInFinalReport(tenableReports);

//		printMergedTenableReport(tenableReports);

		createBriefReport(tenableReports, modifiedK2Reports, briefReports);

		createCompareReport(tenableReports, modifiedK2Reports, compareReport);

		CSVWriter.writeMergedReport(tenableReports);
//		CSVWriter.writeBriefReport(briefReports);
		CSVWriter.writeCompareReport(compareReport);

		TenablePDFWriter.write(tenableReports);
	}

}
