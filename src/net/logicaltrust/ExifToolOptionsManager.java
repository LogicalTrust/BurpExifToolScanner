package net.logicaltrust;

import java.util.Arrays;
import java.util.List;

import burp.IBurpExtenderCallbacks;

public class ExifToolOptionsManager {

	private final String PASSIVE_SCAN = "PASSIVE_SCAN";
	private final String MESSAGE_EDITOR = "MESSAGE_EDITOR";
	private final String MIME_TYPES_TO_IGNORE = "MIME_TYPES_TO_IGNORE";
	
	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolScannerCheck scanner;
	private final ExifToolEditorTabFactory tabFactory;
	private final ExifToolProcess exiftoolProcess;

	public ExifToolOptionsManager(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess,
			ExifToolScannerCheck scanner, ExifToolEditorTabFactory tabFactory) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.scanner = scanner;
		this.tabFactory = tabFactory;
		
		if (Boolean.parseBoolean(callbacks.loadExtensionSetting(PASSIVE_SCAN))) {
			callbacks.registerScannerCheck(scanner);
		}
		
		if (Boolean.parseBoolean(callbacks.loadExtensionSetting(MESSAGE_EDITOR))) {
			callbacks.registerMessageEditorTabFactory(tabFactory);
		}
		
		String mimeTypes = callbacks.loadExtensionSetting(MIME_TYPES_TO_IGNORE);
		List<String> mimeTypesToIgnore = mimeTypes != null ? Arrays.asList(mimeTypes.split("\n")) : Arrays.asList("HTML", "JSON", "script", "CSS");
		exiftoolProcess.setTypesToIgnore(mimeTypesToIgnore);
	}
	
	public void changePassiveScan(boolean on) {
		callbacks.saveExtensionSetting(PASSIVE_SCAN, Boolean.toString(on));
		if (on) { 
			callbacks.registerScannerCheck(scanner); 
		} else {
			callbacks.removeScannerCheck(scanner);
		}
	}
	
	public void changeMessageEditor(boolean on) {
		callbacks.saveExtensionSetting(MESSAGE_EDITOR, Boolean.toString(on));
		if (on) {
			callbacks.registerMessageEditorTabFactory(tabFactory);
		} else {
			callbacks.removeMessageEditorTabFactory(tabFactory);
		}
	}
	
	public void updateMimeTypesToIgnore(List<String> mimeTypes) {
		callbacks.saveExtensionSetting(MIME_TYPES_TO_IGNORE, String.join("\n", mimeTypes));
		exiftoolProcess.setTypesToIgnore(mimeTypes);
	}
	
	
}
