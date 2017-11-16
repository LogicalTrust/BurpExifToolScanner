package net.logicaltrust;

import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import burp.IMessageEditorTab;
import burp.ITextEditor;

public class ExifToolEditorTab implements IMessageEditorTab {

	private final ITextEditor textEditor;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger logger;
	private static final ExecutorService POOL = Executors.newCachedThreadPool();

	public ExifToolEditorTab(ITextEditor textEditor, ExifToolProcess exiftoolProcess, SimpleLogger logger) {
		this.textEditor = textEditor;
		this.logger = logger;
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
		boolean enabled = false;
		if (!isRequest && content.length > 0) {
			enabled = exiftoolProcess.canReadMetadata(content);
		}
		logger.debug("IMessageEditorTab isEnabled: " + enabled);
		return enabled;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (!isRequest && content.length > 0) {
			POOL.execute(() -> {
				try {
					List<String> metadata = exiftoolProcess.readMetadata(content);
					if (!metadata.isEmpty()) {
						String metadataText = String.join("\n", metadata);
						textEditor.setText(metadataText.getBytes(StandardCharsets.UTF_8));
						logger.debug("Metadata read from exiftool [IMessageEditorTab] ");
					} else {
						logger.debug("No data read from exiftool [IMessageEditorTab]");
					}
				} catch (Exception e) {
					e.printStackTrace(logger.getStderr());
				}
			});
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
