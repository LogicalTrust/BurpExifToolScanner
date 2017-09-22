package net.logicaltrust.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import burp.ITab;
import net.logicaltrust.ExifToolOptionsManager;

public class ExifToolPanel extends JPanel implements ITab {

	private static final long serialVersionUID = 1L;

	public ExifToolPanel(ExifToolOptionsManager optionsManager) {
		setLayout(new BorderLayout(0, 0));
		
		JPanel githubPanel = new JPanel();
		githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		add(githubPanel, BorderLayout.SOUTH);
		githubPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel githubLabel = new JLabel("https://github.com/LogicalTrust");
		githubPanel.add(githubLabel);
		
		JPanel checkboxPanel = new JPanel();
		add(checkboxPanel, BorderLayout.NORTH);
		checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JCheckBox chckbxPassiveScan = new JCheckBox("Passive Scan");
		checkboxPanel.add(chckbxPassiveScan);
		chckbxPassiveScan.addActionListener(e -> optionsManager.changePassiveScan(chckbxPassiveScan.isSelected()));
		if (optionsManager.isPassiveScanOn()) {
			chckbxPassiveScan.doClick();
		}
	
		JCheckBox chckbxMessageEditor = new JCheckBox("Message Editor");
		checkboxPanel.add(chckbxMessageEditor);
		chckbxMessageEditor.addActionListener(e -> optionsManager.changeMessageEditor(chckbxMessageEditor.isSelected()));
		if (optionsManager.isMessageEditorOn()) {
			chckbxMessageEditor.doClick();
		}
		
		JPanel tablesPanel = new JPanel();
		add(tablesPanel, BorderLayout.CENTER);
		tablesPanel.setLayout(new GridLayout(0, 2, 0, 0));
		
		JPanel mimeTable = new ExifToolTable("Ignore MIME Types", "Do not scan specified MIME Types. The possible values are the same as those used in the main Burp UI",
				optionsManager.getMimeTypesToIgnore(), 
				optionsManager.getDefaultMimeTypesToIgnore(), 
				optionsManager::updateMimeTypesToIgnore);
		tablesPanel.add(mimeTable);
		
		JPanel fieldsTable = new ExifToolTable("Ignore result lines", "Do not print lines with specified tags.",
				optionsManager.getLinesToIgnore(), 
				optionsManager.getDefaultLinesToIgnore(), 
				optionsManager::updateLinesToIgnore);
		tablesPanel.add(fieldsTable);
	}
	
	@Override
	public String getTabCaption() {
		return "ExifTool";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}
	
}
