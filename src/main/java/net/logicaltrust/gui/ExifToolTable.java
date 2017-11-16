package net.logicaltrust.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

public class ExifToolTable extends JPanel {

	private static final long serialVersionUID = 1L;

	public ExifToolTable(String title, String tooltip, Collection<String> values, Collection<String> defaultValues, 
			Consumer<Collection<String>> updateValues, PrintWriter stderr) {
		
		this.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0)), title, TitledBorder.LEADING, TitledBorder.TOP, null, null));
		this.setToolTipText(tooltip);
		this.setLayout(new BorderLayout(0, 0));
		
		ExifToolTableModel model = new ExifToolTableModel(values, stderr);
		
		JPanel buttonPanel = new JPanel();
		this.add(buttonPanel, BorderLayout.WEST);
		GridBagLayout buttonPanelLayout = new GridBagLayout();
		buttonPanelLayout.columnWidths = new int[] {50};
		buttonPanelLayout.rowHeights = new int[] {0, 0, 0, 25};
		buttonPanelLayout.columnWeights = new double[]{0.0};
		buttonPanelLayout.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		buttonPanel.setLayout(buttonPanelLayout);
		
		JButton addButton = new JButton("Add");
		buttonPanel.add(addButton, createTableButtonConstraints(0));
		
		JButton deleteButton = new JButton("Delete");
		buttonPanel.add(deleteButton, createTableButtonConstraints(1));
		
		JButton defaultButton = new JButton("Default");
		buttonPanel.add(defaultButton, createTableButtonConstraints(2));
		defaultButton.addActionListener(e -> {
			model.replaceAll(defaultValues);
			model.fireTableDataChanged();
		}); 
		
		JButton undoButton = new JButton("Undo");
		buttonPanel.add(undoButton, createTableButtonConstraints(3));
		undoButton.setEnabled(false);
		undoButton.addActionListener(e -> model.undo());
		
		JTable table = new JTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		this.add(table, BorderLayout.CENTER);
		
		model.addTableModelListener(e -> {
			undoButton.setEnabled(model.canUndo());
			int c = model.getRowCount();
			Set<String> modelValues = new LinkedHashSet<>(c);
			for (int i = 0; i < c; i++) {
				modelValues.add((String) model.getValueAt(i, 0)); 
			}
			updateValues.accept(modelValues);
		});
		
		table.setModel(model);
		
		deleteButton.addActionListener(e -> {
			int selectedRow = table.getSelectedRow();
			if (selectedRow != -1) {
				model.removeRow(selectedRow);
				model.fireTableDataChanged();
			}
		});
		
		addButton.addActionListener((e) -> {
			String value = JOptionPane.showInputDialog("Insert value");
			if (value != null) {
				model.addRow(new Object[] { value });
				model.fireTableDataChanged();
			}
		});
	}
	
	private GridBagConstraints createTableButtonConstraints(int index) {
		GridBagConstraints btnConstraints = new GridBagConstraints();
		btnConstraints.fill = GridBagConstraints.HORIZONTAL;
		btnConstraints.anchor = GridBagConstraints.NORTH;
		btnConstraints.gridx = 0;
		btnConstraints.gridy = index;
		return btnConstraints;
	}

}
