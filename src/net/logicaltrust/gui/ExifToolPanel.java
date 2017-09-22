package net.logicaltrust.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;

import burp.ITab;
import net.logicaltrust.ExifToolOptionsManager;

public class ExifToolPanel extends JPanel implements ITab, TableModelListener {

	private static final long serialVersionUID = 1L;
	private JTable mimeTypesTable;
	private DefaultTableModel mimeTypesModel;
	private ExifToolOptionsManager optionsManager;

	public ExifToolPanel(ExifToolOptionsManager optionsManager) {
		this.optionsManager = optionsManager;
		setLayout(new BorderLayout(0, 0));
		
		JPanel mimeTypesPanel = new JPanel();
		mimeTypesPanel.setToolTipText("MIME Type - the possible values are the same as those used in the main Burp UI");
		mimeTypesPanel.setBorder(new TitledBorder(new EmptyBorder(30, 20, 10, 20), "Ignore MIME Types", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
		add(mimeTypesPanel, BorderLayout.CENTER);
		mimeTypesPanel.setLayout(new BorderLayout(0, 0));

		mimeTypesTable = new JTable();
		mimeTypesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		mimeTypesPanel.add(mimeTypesTable, BorderLayout.CENTER);
		mimeTypesModel = new DefaultTableModel(new String[] { "type" }, 0);
		for (String type : optionsManager.getMimeTypesToIgnore()) {
			mimeTypesModel.addRow(new Object[] { type });
		}
		mimeTypesTable.setModel(mimeTypesModel);
		mimeTypesModel.addTableModelListener(this);
		
		JPanel githubPanel = new JPanel();
		githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		add(githubPanel, BorderLayout.SOUTH);
		githubPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel githubLabel = new JLabel("https://github.com/LogicalTrust");
		githubPanel.add(githubLabel);
		
		JPanel buttonsPanel = new JPanel();
		add(buttonsPanel, BorderLayout.WEST);
		GridBagLayout gbl_buttonsPanel = new GridBagLayout();
		gbl_buttonsPanel.columnWidths = new int[] {50};
		gbl_buttonsPanel.rowHeights = new int[]{25, 0, 0, 0};
		gbl_buttonsPanel.columnWeights = new double[]{0.0};
		gbl_buttonsPanel.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		buttonsPanel.setLayout(gbl_buttonsPanel);
		
		JButton btnDelete = new JButton("Delete");
		GridBagConstraints gbc_btnDelete = new GridBagConstraints();
		gbc_btnDelete.insets = new Insets(0, 0, 5, 0);
		gbc_btnDelete.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnDelete.gridx = 0;
		gbc_btnDelete.gridy = 1;
		btnDelete.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int selectedRow = mimeTypesTable.getSelectedRow();
				if (selectedRow > -1) {
					mimeTypesModel.removeRow(selectedRow);
					mimeTypesModel.fireTableDataChanged();
				}
			}
		});
		buttonsPanel.add(btnDelete, gbc_btnDelete);
		
		JButton btnUndoDelete = new JButton("Undo");
		btnUndoDelete.setVerticalAlignment(SwingConstants.BOTTOM);
		GridBagConstraints gbc_btnUndoDelete = new GridBagConstraints();
		gbc_btnUndoDelete.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnUndoDelete.insets = new Insets(0, 0, 5, 0);
		gbc_btnUndoDelete.gridx = 0;
		gbc_btnUndoDelete.gridy = 2;
		buttonsPanel.add(btnUndoDelete, gbc_btnUndoDelete);
		
		JButton btnNewButton = new JButton("Add");
		GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
		gbc_btnNewButton.insets = new Insets(0, 0, 5, 0);
		gbc_btnNewButton.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnNewButton.gridx = 0;
		gbc_btnNewButton.gridy = 0;
		btnNewButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String value = JOptionPane.showInputDialog("MIME Type");
				if (value != null) {
					mimeTypesModel.addRow(new Object[] { value });
					mimeTypesModel.fireTableDataChanged();
				}
			}
		});
		buttonsPanel.add(btnNewButton, gbc_btnNewButton);
		
		JPanel checkboxPanel = new JPanel();
		add(checkboxPanel, BorderLayout.NORTH);
		checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JCheckBox chckbxPassiveScan = new JCheckBox("Passive Scan");
		checkboxPanel.add(chckbxPassiveScan);
		chckbxPassiveScan.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				optionsManager.changePassiveScan(chckbxPassiveScan.isSelected());
			}
		});
		if (optionsManager.isPassiveScanOn()) {
			chckbxPassiveScan.doClick();
		}
	
		JCheckBox chckbxMessageEditor = new JCheckBox("Message Editor");
		checkboxPanel.add(chckbxMessageEditor);
		chckbxMessageEditor.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				optionsManager.changeMessageEditor(chckbxMessageEditor.isSelected());
			}
		});
		if (optionsManager.isMessageEditorOn()) {
			chckbxMessageEditor.doClick();
		}
		mimeTypesTable.getColumnModel().getColumn(0).setResizable(false);
	}
	
	private void notifyAboutMimeTypesChange() {
		int rowCount = mimeTypesModel.getRowCount();
		List<String> mimeTypes = new ArrayList<>(rowCount);
		for (int i = 0; i < rowCount; i++) {
			mimeTypes.add((String) mimeTypesModel.getValueAt(i, 0));
		}
		optionsManager.updateMimeTypesToIgnore(mimeTypes);
	}

	@Override
	public String getTabCaption() {
		return "ExifTool";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}

	@Override
	public void tableChanged(TableModelEvent e) {
		notifyAboutMimeTypesChange();
	}
}
