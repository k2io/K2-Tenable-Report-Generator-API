package com.k2cybersecurity.tenable.reportgenerator;

import java.io.FileNotFoundException;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.itextpdf.kernel.color.Color;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.Style;
import com.itextpdf.layout.element.AreaBreak;
import com.itextpdf.layout.element.LineSeparator;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.property.HorizontalAlignment;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.text.Chunk;
import com.itextpdf.text.pdf.draw.DottedLineSeparator;
import com.k2cybersecurity.tenable.models.TenableReport;

public class TenablePDFWriter {

	public static void write(List<TenableReport> tenableReports) {
		String filename = "/Users/prateek/Downloads/K2-Tenable-Report.pdf";
		PdfWriter writer;
		try {
			writer = new PdfWriter(filename);
			PdfDocument pdf = new PdfDocument(writer);
			Document document = new Document(pdf);
			System.out.println(tenableReports.size());
			document.add(new Paragraph("K2 & Tenable Joint report").setBackgroundColor(Color.GRAY).setBold()
					.setBackgroundColor(Color.DARK_GRAY).setFontColor(Color.WHITE).setBold()
					.setTextAlignment(TextAlignment.CENTER).setFontSize(20f));

			for (TenableReport tenableReport : tenableReports) {
				if (tenableReport.getPluginID() == "Summary") {
					document.add(new Paragraph(tenableReport.getDescription()));
				} else if (tenableReport.getPluginID() == "K2") {
					document.add(new Paragraph(tenableReport.getName()).setFontColor(Color.BLUE).setUnderline());
					document.add(new Paragraph(tenableReport.getK2output()));
				} else {
					document.add(new Paragraph(tenableReport.getName()).setFontColor(Color.BLUE).setUnderline());
					System.out.println(tenableReport.getName() + " ---- " + tenableReport.getTenablePluginOutput().getUrl()); 
					if (tenableReport.getTenablePluginOutput().getUrl() != null) {
						if (StringUtils.isNotBlank(tenableReport.getTenablePluginOutput().getUrl())) {
							document.add(new Paragraph("URL : " + tenableReport.getTenablePluginOutput().getUrl()));
						}
						if (tenableReport.getTenablePluginOutput().getDetectionInformation() != null) {
							String di = "";

							for (String str : tenableReport.getTenablePluginOutput().getDetectionInformation()
									.keySet()) {
								di += str + " : ";
								di += tenableReport.getTenablePluginOutput().getDetectionInformation().get(str) + "\n";
							}
							document.add(new Paragraph("Detection Information : \n" + di));
						}
					} else {
						System.out.println(tenableReport.getName() + " +++++ " + tenableReport.getPluginOutput());
						if (StringUtils.isNotBlank(tenableReport.getPluginOutput())) {
							document.add(new Paragraph("Plugin Output: \n" + tenableReport.getPluginOutput()));
						}
					}
					document.add(new Paragraph("Risk : " + tenableReport.getRisk()));
					document.add(new Paragraph(tenableReport.getK2output()));
				}
				document.add(new AreaBreak());
			}
			document.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

	}

//	public static void main(String[] args) {
//		write();
//	}

}
