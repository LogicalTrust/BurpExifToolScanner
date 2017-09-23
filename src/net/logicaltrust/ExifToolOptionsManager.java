package net.logicaltrust;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;

public class ExifToolOptionsManager {

	private static final Collection<String> DEFAULT_MIME_TYPES_TO_IGNORE = Arrays.asList("HTML", "JSON", "script", "CSS");
	private static final Collection<String> DEFAULT_LINES_TO_IGNORE = Arrays.asList("ExifToolVersion", "Error", "Directory", "FileAccessDate", "FileInodeChangeDate", "FileModifyDate", "FileName", "FilePermissions", "FileSize");
	private static final String DELIMETER = "\n";
	
	private final String PASSIVE_SCAN = "PASSIVE_SCAN";
	private final String MESSAGE_EDITOR = "MESSAGE_EDITOR";
	private final String MIME_TYPES_TO_IGNORE = "MIME_TYPES_TO_IGNORE";
	private final String LINES_TO_IGNORE = "LINES_TO_IGNORE";
	
	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolScannerCheck scanner;
	private final ExifToolEditorTabFactory tabFactory;
	private final ExifToolProcess exiftoolProcess;
	@SuppressWarnings("unused")
	private final PrintWriter stdout;

	public ExifToolOptionsManager(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess,
			ExifToolScannerCheck scanner, ExifToolEditorTabFactory tabFactory, PrintWriter stdout) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.scanner = scanner;
		this.tabFactory = tabFactory;
		this.stdout = stdout;
		exiftoolProcess.setTypesToIgnore(getMimeTypesToIgnore());
		exiftoolProcess.setLinesToIgnore(getLinesToIgnore());
	}
	
	public boolean isPassiveScanOn() {
		return Boolean.parseBoolean(loadSettingWithFallback(PASSIVE_SCAN));
	}
	
	public boolean isMessageEditorOn() {
		return Boolean.parseBoolean(loadSettingWithFallback(MESSAGE_EDITOR)); 
	}
	
	private String loadSettingWithFallback(String optionName) {
		String setting = callbacks.loadExtensionSetting(optionName);
		return setting != null ? setting : "true";
	}
	
	private Collection<String> getIgnoreSettings(String settingName, Collection<String> fallback) {
		String settingsSerialized = callbacks.loadExtensionSetting(settingName);
		Collection<String> settings = settingsSerialized != null ? Arrays.stream(settingsSerialized.split(DELIMETER)).collect(Collectors.toCollection(LinkedHashSet::new)) : fallback;
		return settings;
	}
	
	public Collection<String> getMimeTypesToIgnore() {
		return getIgnoreSettings(MIME_TYPES_TO_IGNORE, DEFAULT_MIME_TYPES_TO_IGNORE);
	}
	
	public Collection<String> getLinesToIgnore() {
		return getIgnoreSettings(LINES_TO_IGNORE, DEFAULT_LINES_TO_IGNORE);
	}
	
	public Collection<String> getDefaultMimeTypesToIgnore() {
		return DEFAULT_MIME_TYPES_TO_IGNORE;
	}
	
	public Collection<String> getDefaultLinesToIgnore() {
		return DEFAULT_LINES_TO_IGNORE;
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
	
	public void updateMimeTypesToIgnore(Collection<String> mimeTypes) {
		callbacks.saveExtensionSetting(MIME_TYPES_TO_IGNORE, String.join(DELIMETER, mimeTypes));
		exiftoolProcess.setTypesToIgnore(mimeTypes);
	}
	
	public void updateLinesToIgnore(Collection<String> lines) {
		callbacks.saveExtensionSetting(LINES_TO_IGNORE, String.join(DELIMETER, lines));
		exiftoolProcess.setLinesToIgnore(lines);
	}
	
	
}
