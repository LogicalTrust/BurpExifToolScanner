package net.logicaltrust.gui;

import java.util.Vector;

class RemoveRowUndoAction implements UndoAction {

	private final Vector<Object> value;
	private final int row;

	public RemoveRowUndoAction(Vector<Object> value, int row) {
		this.value = value;
		this.row = row;
	}

	@Override
	public void undo(ExifToolTableModel exifToolTableModel) {
		exifToolTableModel.undoRemoveRow(value, row);
	}

}
