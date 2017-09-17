package net.logicaltrust;

import java.io.PrintWriter;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class ExifToolEditorTabFactory implements IMessageEditorTabFactory {

	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolProcess exiftoolProcess;
	private final PrintWriter stderr;

	public ExifToolEditorTabFactory(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess, PrintWriter stderr) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.stderr = stderr;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new ExifToolEditorTab(callbacks.createTextEditor(), exiftoolProcess, stderr);
	}

}
