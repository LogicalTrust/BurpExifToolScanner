package net.logicaltrust.gui;

class AddRowUndoAction implements UndoAction {

	private final int rowCount;

	public AddRowUndoAction(int rowCount) {
		this.rowCount = rowCount;
	}

	@Override
	public void undo(ExifToolTableModel exifToolTableModel) {
		exifToolTableModel.undoAddRow(rowCount);
	}

}
