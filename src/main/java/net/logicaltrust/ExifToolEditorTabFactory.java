package net.logicaltrust;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class ExifToolEditorTabFactory implements IMessageEditorTabFactory {

	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger logger;

	public ExifToolEditorTabFactory(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess, SimpleLogger logger) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.logger = logger;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new ExifToolEditorTab(callbacks.createTextEditor(), exiftoolProcess, logger);
	}

}
