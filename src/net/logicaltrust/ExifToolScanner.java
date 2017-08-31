package net.logicaltrust;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class ExifToolScanner implements IScannerCheck {

	private final IExtensionHelpers helpers;
	private static final List<String> TYPES_TO_IGNORE = Arrays.asList("HTML", "JSON", "script", "CSS");
	private static final String FILETYPE_KEY = "FileType: ";

	public ExifToolScanner(IExtensionHelpers helpers) {
		this.helpers = helpers;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
		List<IScanIssue> issues = null;
		if (!TYPES_TO_IGNORE.contains(responseInfo.getStatedMimeType()) 
				&& !TYPES_TO_IGNORE.contains(responseInfo.getInferredMimeType())) {
			try {
				issues = exiftoolScan(baseRequestResponse, responseInfo);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return issues;
	}
	
	private List<IScanIssue> exiftoolScan(IHttpRequestResponse baseRequestResponse, IResponseInfo responseInfo) throws IOException {
		Process process = new ProcessBuilder(new String[] { "exiftool", "-m", "-q", "-q", "-S", "-E", "-sort", "-" }).start();
		
		OutputStream outputStream = process.getOutputStream();
		outputStream.write(baseRequestResponse.getResponse(), responseInfo.getBodyOffset(), baseRequestResponse.getResponse().length - responseInfo.getBodyOffset());
		outputStream.close();
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		StringBuilder details = new StringBuilder();
		String line;
		String filetype = "";
		while ((line = reader.readLine()) != null) {
			if (!line.startsWith("ExifToolVersion:") && !line.startsWith("Error:")) {
				details.append("<li>").append(line).append("</li>");
				if (line.startsWith(FILETYPE_KEY)) {
					filetype = " in " + line.substring(FILETYPE_KEY.length());
				}
			}
		}
		
		if (details.length() > 0) {
			details.insert(0, "<ul>").append("</ul>");
			URL url = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()).getUrl();
			ExifToolScanIssue i = new ExifToolScanIssue(url, 
					details.toString(), 
					new IHttpRequestResponse[] { baseRequestResponse }, 
					baseRequestResponse.getHttpService(),
					"Metadata" + filetype + " (ExifTool)");
			return Arrays.asList(i);
		}
		
		return null;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ? -1 : 0;
	}

}
