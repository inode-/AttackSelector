package burp;

import java.util.List;
import javax.swing.table.AbstractTableModel;

public class ConfigurationTableModel extends AbstractTableModel {

	private final List<Configuration> configurationList;

	private static final long serialVersionUID = 1L;

	private final String[] columnNames = new String[] { "Enabled", "Name" };

	private final Class<?>[] columnClass = new Class<?>[] { Boolean.class, String.class };

	public ConfigurationTableModel(List<Configuration> configurationList) {
		this.configurationList = configurationList;
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columnClass[columnIndex];
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public int getRowCount() {
		return configurationList.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Configuration row = configurationList.get(rowIndex);
		if (0 == columnIndex) {
			return row.getEnabled();
		} else if (1 == columnIndex) {
			return row.getName();
		}

		return null;
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int colIndex) {
		Configuration row = configurationList.get(rowIndex);
		switch (colIndex) {
		case 0:
			row.setEnabled((Boolean) value);
			break;
		case 1:
			row.setName(value.toString());
			break;
		}
		fireTableRowsUpdated(rowIndex, colIndex);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if( rowIndex == 0 )
			return false;
		
		return true;
	}
}
