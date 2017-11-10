package net.logicaltrust;

import java.awt.Component;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

import burp.IMessageEditorTab;
import burp.ITextEditor;

public class ExifToolEditorTab implements IMessageEditorTab {

	private final ITextEditor textEditor;
	private final ExifToolProcess exiftoolProcess;
	private final PrintWriter stderr;

	public ExifToolEditorTab(ITextEditor textEditor, ExifToolProcess exiftoolProcess, PrintWriter stderr) {
		this.textEditor = textEditor;
		this.stderr = stderr;
		textEditor.setEditable(false);
		this.exiftoolProcess = exiftoolProcess;
	}

	@Override
	public String getTabCaption() {
		return "Metadata (ExifTool)";
	}

	@Override
	public Component getUiComponent() {
		return textEditor.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		if (!isRequest && content.length > 0) {
			return exiftoolProcess.canReadMetadata(content);
		}
		return false;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (!isRequest && content.length > 0) {
			try {
				List<String> metadata = exiftoolProcess.readMetadata(content);
				if (!metadata.isEmpty()) {
					String metadataText = String.join("\n", metadata);
					textEditor.setText(metadataText.getBytes(StandardCharsets.UTF_8));
				}
			} catch (Exception e) {
				e.printStackTrace(stderr);
			}
		}
	}

	@Override
	public byte[] getMessage() {
		return textEditor.getText();
	}

	@Override
	public boolean isModified() {
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		return textEditor.getSelectedText();
	}

}
