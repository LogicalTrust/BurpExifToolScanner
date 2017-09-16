package net.logicaltrust;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class ExifToolScanner implements IScannerCheck {

	private static final String FILETYPE_KEY = "FileType: ";

	private final IExtensionHelpers helpers;
	private final ExifToolProcess exiftoolProcess;
	private final PrintWriter stderr;

	public ExifToolScanner(IExtensionHelpers helpers, ExifToolProcess exiftoolProcess, PrintWriter stderr) throws ExtensionInitException {
		this.helpers = helpers;
		this.exiftoolProcess = exiftoolProcess;
		this.stderr = stderr;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		try {
			List<String> metadata = exiftoolProcess.readMetadataHtml(baseRequestResponse.getResponse());
			if (!metadata.isEmpty()) {
				URL url = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()).getUrl();
				StringBuilder list = new StringBuilder("<ul>");
				String filetype = "";
				for (String line : metadata) {
					list.append("<li>").append(line).append("</li>");
					if (line.startsWith(FILETYPE_KEY)) {
						filetype = " in " + line.substring(FILETYPE_KEY.length());
					}
				}
				ExifToolScanIssue i = new ExifToolScanIssue(url, 
						list.toString(), 
						new IHttpRequestResponse[] { baseRequestResponse }, 
						baseRequestResponse.getHttpService(),
						"Metadata" + filetype + " (ExifTool)");
				return Arrays.asList(i);
				
			}
		} catch (IOException e) {
			e.printStackTrace(stderr);
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
