package com.k2cybersecurity.tenable.reportgenerator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class GetScannedReports {
	private static String tenableUrl = "https://cloud.tenable.com";
	private static String XApiKeys = "";
	private static String k2Url = "https://www.k2io.net/centralmanager";
	private static String k2CustomerId = "";
	private static String k2CustomerEmail = "";
	private static String k2CustomerPassword = "";
	private static Long startTime;
	private static Long endTime;
	private static String exportedFileName = StringUtils.EMPTY;
	private static final String COOKIES_HEADER = "Set-Cookie";
	private static java.net.CookieManager cookieManager = new java.net.CookieManager();

	private static void tenableScanInfo(String SCAN_ID) {
		String url = tenableUrl + "/scans/" + SCAN_ID;
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.setRequestMethod("GET");
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			JSONObject info = (JSONObject) json.get("info");
			System.out.println("Tenable Scan info for ID: " + SCAN_ID + "\n" + info.toJSONString());
			System.out.println("Tenable Scan Start Timestamp : " + info.get("scan_start"));
			startTime = (Long) info.get("scan_start") * 1000;
			System.out.println("Tenable Scan End Timestamp : " + info.get("scan_end"));
			endTime = (Long) info.get("scan_end") * 1000;

		} catch (IOException | ParseException e) {
			e.printStackTrace();
		}
	}

	private static void tenableExportReport(String SCAN_ID) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.setRequestProperty("content-type", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.setDoOutput(true);
			httpClient.setRequestMethod("POST");

			String body = "{\"format\":\"csv\"}";
			try (OutputStream os = httpClient.getOutputStream()) {
				byte[] input = body.getBytes("utf-8");
				os.write(input, 0, input.length);
			}

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			System.out.println("Tenable Report Export Response : " + json.toJSONString());
			exportedFileName = (String) json.get("file");
			System.out.println("File name : " + exportedFileName);
//			System.out.println("Sleep 60 sec for extracting report");
//			try {
//				TimeUnit.SECONDS.sleep(60);
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
		} catch (IOException | ParseException e) {
			e.printStackTrace();
		}
	}

	private static boolean tenableExportStatus(String SCAN_ID, String exportedFileName) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export/" + exportedFileName + "/status?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.setRequestMethod("GET");

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			JSONParser parser = new JSONParser();
			JSONObject json = (JSONObject) parser.parse(response);
			System.out.println("Tenable Export Status Response : " + json.toJSONString());
			String status = (String) json.get("status");
			System.out.println("Status : " + status);
			if (StringUtils.equals(status, "ready")) {
				return true;
			} else {
				return false;
			}
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static void tenableDownloadReport(String SCAN_ID, String OUTPUT_DIR, String exportedFileName) {
		String url = tenableUrl + "/scans/" + SCAN_ID + "/export/" + exportedFileName + "/download?type=web-app";
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Accept", "application/json");
			httpClient.addRequestProperty("X-ApiKeys", XApiKeys);
			httpClient.setRequestMethod("GET");

			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
//			String line;
//			while ((line = response.readLine()) != null) {
//				System.out.println(line);
//				System.out.flush();
//			}
//			System.out.println("Download Response : " + response.readLine());
//			System.out.println("Download Response : " + response.readLine());
			System.out.println("Saving Tenable Report in file : " + OUTPUT_DIR + "/Tenable-Report.csv");
			IOUtils.copy(response, new FileOutputStream(new File(OUTPUT_DIR + "/Tenable-Report.csv")), "utf-8");
			response.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void k2Session() {
		String url = k2Url + "/login";
		try {
			HttpsURLConnection httpClient = (HttpsURLConnection) new URL(url).openConnection();
			httpClient.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
			httpClient.setDoOutput(true);
			httpClient.setRequestMethod("POST");
			String body = "j_username=" + k2CustomerEmail + "&j_password=" + k2CustomerPassword;
			try (OutputStream os = httpClient.getOutputStream()) {
				byte[] input = body.getBytes("utf-8");
				os.write(input, 0, input.length);
			}
			Map<String, List<String>> headerFields = httpClient.getHeaderFields();
			List<String> cookiesHeader = headerFields.get(COOKIES_HEADER);

			if (cookiesHeader != null) {
				for (String cookie : cookiesHeader) {
					cookieManager.getCookieStore().add(null, HttpCookie.parse(cookie).get(0));
				}
			}
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
			String res = response.readLine();
			System.out.println("K2 Login Response : " + res);
			if (StringUtils.equals(res, "ok")) {
				System.out.println("Logged in successfully, Session created.");
			}
			IOUtils.copy(response, new FileOutputStream(new File("/Users/prateek/Downloads/k2output.csv")), "utf-8");
			response.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void k2DownloadReport(String OUTPUT_DIR) {
		String url = k2Url + "/api/v1/incident/attack/csv/" + k2CustomerId + "?startTime=" + startTime + "&endTime="
				+ endTime;
		try {
			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
			httpClient.setRequestMethod("GET");

			if (cookieManager.getCookieStore().getCookies().size() > 0) {
				httpClient.setRequestProperty("Cookie",
						StringUtils.join(cookieManager.getCookieStore().getCookies(), ';'));
			}
			BufferedReader response = new BufferedReader(new InputStreamReader(httpClient.getInputStream()));
//			String line;
//			while ((line = response.readLine()) != null) {
//				System.out.println(line);
//				System.out.flush();
//			}
//			System.out.println("Response : " + response);
			System.out.println("Saving K2 Report in file : " + OUTPUT_DIR + "/K2-Report.csv");
			IOUtils.copy(response, new FileOutputStream(new File(OUTPUT_DIR + "/K2-Report.csv")), "utf-8");
			response.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

//	private static JSONObject getECSInfo() {
//		try {
//			String url = System.getenv("ECS_CONTAINER_METADATA_URI");
//			HttpURLConnection httpClient = (HttpURLConnection) new URL(url).openConnection();
//			String response = new String(
//					IOUtils.readFully(httpClient.getInputStream(), httpClient.getInputStream().available()));
//			JSONParser parser = new JSONParser();
//			JSONObject json = (JSONObject) parser.parse(response);
//			return json;
//		} catch (IOException | org.json.simple.parser.ParseException e) {
//			return null;
//		}
//	}

	public static void run(String SCAN_ID, String OUTPUT_DIR) {
		tenableScanInfo(SCAN_ID);
		tenableExportReport(SCAN_ID);
		if (StringUtils.isNotBlank(exportedFileName)) {
			int retry = 5;
			while (retry-- > 0) {
				if (tenableExportStatus(SCAN_ID, exportedFileName)) {
					tenableDownloadReport(SCAN_ID, OUTPUT_DIR, exportedFileName);
					break;
				}
				try {
					System.out.println("Report not extracted yet, retrying...");
					TimeUnit.SECONDS.sleep(60);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			if (retry == 0) {
				System.out.println("Tenable Report not extracted properly");
			}
		} else {
			System.out.println("Tenable report not extracted.");
		}

		k2Session();
		k2DownloadReport(OUTPUT_DIR);
	}

//	public static void main(String[] args) {
//		System.out.println("Working Directory = " + System.getProperty("user.dir"));
//		tenableScanInfo();
//		String exportedFileName = tenableExportReport();
//		System.out.println("sun :" + exportedFileName);
//		if (StringUtils.isNotBlank(exportedFileName) && tenableExportStatus(exportedFileName)) {
//			System.out.println("in if");
//			tenableDownloadReport(exportedFileName);
//		}
//		String ses = k2Session();
//		k2DownloadReport(ses);
//	}

}
