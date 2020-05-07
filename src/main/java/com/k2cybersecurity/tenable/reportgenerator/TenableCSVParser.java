package com.k2cybersecurity.tenable.reportgenerator;

import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.k2.models.K2MinifiedOutput;
import com.k2cybersecurity.k2.models.K2Report;
import com.k2cybersecurity.reportgenerator.CSVWriter;
import com.k2cybersecurity.tenable.models.ModifiedK2Report;
import com.k2cybersecurity.tenable.models.TenablePluginOutput;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenableCSVParser {

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

				if (StringUtils.contains(pluginOutput, "URL")) {
					String url = StringUtils.join(lls, "\n", lines.indexOf("URL") + 2,
							lines.indexOf("Detection Information"));
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
			if (k2output1.size() > 0) {
				finalK2Output += "K2 has also detected the same vulnerability with following additional details.\n";
				for (K2MinifiedOutput output : k2output1) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (k2output2.size() > 0) {
				finalK2Output += "K2 has detected following additional attacks or information for this vulnerability\n";
				for (K2MinifiedOutput output : k2output2) {
					finalK2Output += output.toString();
				}
				finalK2Output += "\n\n";
			}
			if (StringUtils.isEmpty(finalK2Output)) {
				String msg = "K2 has not found any attack for this URL.";
				finalK2Output += msg;
			}
			System.out.println("finalK2Output : " + finalK2Output);
			tenableReport.setK2output(finalK2Output);
		}
	}

	private static void addAttacksFoundByOnlyK2(List<TenableReport> tenableReports,
			List<ModifiedK2Report> modifiedK2Reports) {
		for (ModifiedK2Report modifiedK2Report : modifiedK2Reports) {
			if (!modifiedK2Report.isFoundByTenable()) {
				TenableReport tr = new TenableReport();
				tr.setDescription(modifiedK2Report.getAttackDescription());
				tr.setK2output(modifiedK2Report.toString());
				tenableReports.add(tr);
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

	public static void run(String TENABLE_CSV_FILE_PATH, List<K2Report> k2Reports) {
		List<TenableReport> tenableReports = new ArrayList<TenableReport>();
		List<ModifiedK2Report> modifiedK2Reports = new ArrayList<ModifiedK2Report>();

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

		mergeTenableReports(tenableReports, modifiedK2Reports);

		addAttacksFoundByOnlyK2(tenableReports, modifiedK2Reports);

//		printMergedTenableReport(tenableReports);

		CSVWriter.write(tenableReports);

	}

}
