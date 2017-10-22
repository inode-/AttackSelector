/*****************************************************************************
 * PluginQueueTableModel.java part of AttackSelector Burp Plugin             *
 *                                                                           *
 * Copyright (c) 2017, Agazzini Maurizio - inode@mediaservice.net            *
 * All rights reserved.                                                      *
 *                                                                           *
 * Redistribution and use in source and binary forms, with or without        *
 * modification, are permitted provided that the following conditions        *
 * are met:                                                                  *
 *     * Redistributions of source code must retain the above copyright      *
 *       notice, this list of conditions and the following disclaimer.       *
 *     * Redistributions in binary form must reproduce the above copyright   *
 *       notice, this list of conditions and the following disclaimer in     *
 *       the documentation and/or other materials provided with the          *
 *       distribution.                                                       *
 *     * Neither the name of @ Mediaservice.net nor the names of its         *
 *       contributors may be used to endorse or promote products derived     *
 *       from this software without specific prior written permission.       *
 *                                                                           *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,     *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED  *
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    *
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      *
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        *
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              *
 *****************************************************************************/

package burp;

import java.util.List;
import java.net.URL;

import javax.swing.table.AbstractTableModel;

public class PluginQueueTableModel extends AbstractTableModel {

	private final List<PluginQueue> queueList;
	private List<Configuration> configurationList;

	private static final long serialVersionUID = 1L;

	private final String[] columnNames = new String[] { "#", "Host", "Url", "Configuration", "Status" };

	private IExtensionHelpers helpers;

	private final Class<?>[] columnClass = new Class<?>[] { Integer.class, String.class, String.class, String.class,
			String.class };

	public PluginQueueTableModel(List<PluginQueue> queueList, List<Configuration> configurationList,
			IExtensionHelpers helpers) {
		this.queueList = queueList;
		this.helpers = helpers;
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
		return queueList.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {

		PluginQueue row = queueList.get(rowIndex);
		if (0 == columnIndex) {
			return row.getQueueNumber();
		} else if (1 == columnIndex) {
			return row.getMessage().getHttpService().getProtocol() + "://" + row.getMessage().getHttpService().getHost()
					+ ":" + row.getMessage().getHttpService().getPort();
		} else if (2 == columnIndex) {

			IRequestInfo request_info = helpers.analyzeRequest(row.getMessage());
			URL requestUrl = request_info.getUrl();

			String urlPath = requestUrl.getPath();

			if (!requestUrl.getQuery().isEmpty()) {
				urlPath.concat("?");
				urlPath.concat(requestUrl.getQuery());
			}

			return urlPath;

		} else if (3 == columnIndex) {
			return configurationList.get(row.getConfiguration()).getName();
		} else if (4 == columnIndex) {

			switch (row.getStatus()) {

			case 0:
				return "queued";
			case 1:
				return "scanning";
			case 2:
				return "finished";
			case 3:
				return "cancelled";
			}

			return "";
		}

		return null;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {

		return false;
	}

}
