package com.k2cybersecurity.tenable.reportgenerator;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.itextpdf.kernel.color.Color;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.AreaBreak;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.property.TextAlignment;
import com.k2cybersecurity.k2.models.K2MinifiedOutput;
import com.k2cybersecurity.tenable.models.ModifiedK2Report;
import com.k2cybersecurity.tenable.models.TenableFinalReport;

public class TenablePDFWriter {

	public static void write(Map<String, Integer> summaryMap,
			Map<ImmutablePair<String, String>, List<ModifiedK2Report>> onlyK2Detect,
			List<TenableFinalReport> tenableFinalReports) {
		String filename = "/Users/prateek/Downloads/K2-Tenable-Report.pdf";
		PdfWriter writer;
		try {
			writer = new PdfWriter(filename);
			PdfDocument pdf = new PdfDocument(writer);
			Document document = new Document(pdf);
			System.out.println(tenableFinalReports.size());
			document.add(new Paragraph("K2 & TENABLE JOINT REPORT").setBackgroundColor(Color.GRAY).setBold()
					.setBackgroundColor(Color.DARK_GRAY).setFontColor(Color.WHITE).setBold()
					.setTextAlignment(TextAlignment.CENTER).setFontSize(20f));

			document.add(new Paragraph("Summary").setBackgroundColor(Color.ORANGE).setFontColor(Color.BLACK).setBold()
					.setPadding(3f));

			document.add(new Paragraph("Tenable").setUnderline().setFontColor(Color.BLUE));
			document.add(new Paragraph("Total Vulnerabilities = " + summaryMap.get("tenableCount")));
			document.add(new Paragraph("Informational Vulnerabilities = " + summaryMap.get("tenableInformationCount")));
			document.add(new Paragraph("Low Risk Vulnerabilities = " + summaryMap.get("tenableLowCount")));
			document.add(new Paragraph("Medium Risk Vulnerabilities = " + summaryMap.get("tenableMediumCount")));
			document.add(new Paragraph("High Risk Vulnerabilities = " + summaryMap.get("tenableHighCount")));

			document.add(new Paragraph("K2").setUnderline().setFontColor(Color.BLUE));
			document.add(new Paragraph("High Risk Vulnerabilities = " + summaryMap.get("k2HighCount")));

			document.add(new Paragraph("Comparison").setUnderline().setFontColor(Color.BLUE));
			document.add(new Paragraph("Total High Risk Vulnerabilities = " + summaryMap.get("totalCount")));
			document.add(new Paragraph("High Risk Vulnerabilities (Both K2 and Tenable has found) = "
					+ summaryMap.get("commonFindCount")));
			document.add(new Paragraph(
					"High Risk Vulnerabilities (Found by Tenable Only) = " + summaryMap.get("onlyTenableFindCount")));
			document.add(new Paragraph(
					"High Risk Vulnerabilities (Found by K2 Only) = " + summaryMap.get("onlyK2FindCount")));
			document.add(new AreaBreak());

			for (Pair<String, String> pair : onlyK2Detect.keySet()) {

				document.add(new Paragraph("Vulnerability : " + pair.getLeft()).setBackgroundColor(Color.ORANGE)
						.setFontColor(Color.BLACK).setBold().setPadding(3f));
				document.add(new Paragraph("Path : " + pair.getRight()));
				document.add(new Paragraph("Tenable information").setUnderline().setFontColor(Color.BLUE));
				document.add(new Paragraph("Tenable did not detect this vulnerability.")
						.setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				document.add(new Paragraph("K2 information").setUnderline().setFontColor(Color.BLUE));

				List<ModifiedK2Report> list = onlyK2Detect.get(pair);

				String k2Report = "";
				k2Report += "Finding ID: " + list.get(0).getIncidentID();
				k2Report += "\nRisk : High";
				k2Report += "\nFile Name : " + list.get(0).getFileName();
				k2Report += "\nMethod Name : " + list.get(0).getMethodName();
				k2Report += "\nLine Number : " + list.get(0).getLineNumber();
				k2Report += "\nParameters : \n" + list.get(0).getParameterMap();
				k2Report += "\nExecuted Query/Command : " + list.get(0).getExecutedQueryOrCommand();

				document.add(new Paragraph(k2Report).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));

				document.add(new AreaBreak());
			}
			System.out.println("=======================");

			for (TenableFinalReport tenableFinalReport : tenableFinalReports) {
				document.add(new Paragraph("Vulnerability : " + tenableFinalReport.getTenableReport().getName())
						.setBackgroundColor(Color.ORANGE).setFontColor(Color.BLACK).setBold().setPadding(3f));
				if (tenableFinalReport.getTenableReport().getTenablePluginOutput().getUrl() != null) {
					if (StringUtils
							.isNotBlank(tenableFinalReport.getTenableReport().getTenablePluginOutput().getUrl())) {
						document.add(new Paragraph(
								"Path : " + tenableFinalReport.getTenableReport().getTenablePluginOutput().getUrl()));
					}
				}
				document.add(new Paragraph("Tenable information").setUnderline().setFontColor(Color.BLUE));
				String tenableReport = "";

				tenableReport += "Finding ID: " + tenableFinalReport.getTenableReport().getPluginID();
//				document.add(new Paragraph("Finding ID: " + tenableFinalReport.getTenableReport().getPluginID()));
				tenableReport += "\nRisk : " + tenableFinalReport.getTenableReport().getRisk();
//				document.add(new Paragraph("Risk : " + tenableFinalReport.getTenableReport().getRisk()));

				if (tenableFinalReport.getTenableReport().getTenablePluginOutput().getUrl() != null) {
					if (tenableFinalReport.getTenableReport().getTenablePluginOutput()
							.getDetectionInformation() != null) {
						String di = "";

						for (String str : tenableFinalReport.getTenableReport().getTenablePluginOutput()
								.getDetectionInformation().keySet()) {
							di += "\n" + str + " : ";
							di += tenableFinalReport.getTenableReport().getTenablePluginOutput()
									.getDetectionInformation().get(str);
						}
						tenableReport += "\nDetection Information :" + di;
//						document.add(new Paragraph("Detection Information : \n" + di));
					}
				} else {
					System.out.println(tenableFinalReport.getTenableReport().getName() + " +++++ "
							+ tenableFinalReport.getTenableReport().getPluginOutput());
					if (StringUtils.isNotBlank(tenableFinalReport.getTenableReport().getPluginOutput())) {
						tenableReport += "Plugin Output: \n" + tenableFinalReport.getTenableReport().getPluginOutput();
//						document.add(new Paragraph(
//								"Plugin Output: \n" + tenableFinalReport.getTenableReport().getPluginOutput()));
					}
				}

				if (!StringUtils.isEmpty(tenableFinalReport.getTenableReport().getTenablePluginOutput().getProof())) {
					tenableReport += "\nProof : "
							+ tenableFinalReport.getTenableReport().getTenablePluginOutput().getProof();
				}
				document.add(new Paragraph(tenableReport).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				document.add(new Paragraph("K2 information").setUnderline().setFontColor(Color.BLUE));
				String k2Report = "";
				if (tenableFinalReport.getBothDetected() != null && tenableFinalReport.getBothDetected().size() > 0) {
					k2Report += "Risk : High";
					k2Report += "\nFile Name : " + tenableFinalReport.getBothDetected().get(0).getFileName();
					k2Report += "\nMethod Name : " + tenableFinalReport.getBothDetected().get(0).getMethodName();
					k2Report += "\nLine Number : " + tenableFinalReport.getBothDetected().get(0).getLineNumber();
					k2Report += "\nParameters : \n" + tenableFinalReport.getBothDetected().get(0).getParameterMap();
					k2Report += "\nExecuted Query/Command : "
							+ tenableFinalReport.getBothDetected().get(0).getExecutedQueryOrCommand() + "\n\n";
				}
				if (tenableFinalReport.getAdditionalFindings() != null
						&& tenableFinalReport.getAdditionalFindings().size() > 0) {
					k2Report += "K2 has found following additional attack for this vulnerability and URL.";
					k2Report += "\nRisk : High";
					k2Report += "\nFile Name : " + tenableFinalReport.getAdditionalFindings().get(0).getFileName();
					k2Report += "\nMethod Name : " + tenableFinalReport.getAdditionalFindings().get(0).getMethodName();
					k2Report += "\nLine Number : " + tenableFinalReport.getAdditionalFindings().get(0).getLineNumber();
					k2Report += "\nParameters : \n"
							+ tenableFinalReport.getAdditionalFindings().get(0).getParameterMap();

					if (!StringUtils
							.isEmpty(tenableFinalReport.getAdditionalFindings().get(0).getExecutedQueryOrCommand())) {
						k2Report += "\nExecuted Query/Command : "
								+ tenableFinalReport.getAdditionalFindings().get(0).getExecutedQueryOrCommand();
					}

				}
				if (!StringUtils.isEmpty(k2Report)) {
					document.add(new Paragraph(k2Report).setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				}

				if ((tenableFinalReport.getBothDetected() == null || tenableFinalReport.getBothDetected().size() == 0)
						&& (tenableFinalReport.getAdditionalFindings() == null
								|| tenableFinalReport.getAdditionalFindings().size() == 0)) {
					document.add(new Paragraph(
							"K2 did not detect this vulnerability. It is likely a false positive reported by Tenable. Please view K2 logs to confirm or contact K2 team for support.")
									.setBackgroundColor(Color.LIGHT_GRAY).setPadding(5f));
				}
				document.add(new AreaBreak());
			}
			document.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

}
