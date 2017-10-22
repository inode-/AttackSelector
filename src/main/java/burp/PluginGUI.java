/*****************************************************************************
 * PluginGUI.java part of AttackSelector Burp Plugin                         *
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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.json.JSONObject;

/**
 * This class create the GUI components of the plugin
 *
 */
public class PluginGUI implements Runnable, ActionListener, ListSelectionListener, ItemListener {

	JPanel configurationPanel;
	private JTable table;
	JTabbedPane mainPanel;
	private JPanel scan_profiles_panel;
	private JButton buttonAdd;
	private JButton buttonDelete;
	private JScrollPane scrollPane;
	private JTable scan_profile_table;
	private JPanel active_configurator_panel;
	private JLabel lblNewLabel;
	private JLabel label_1;
	private JLabel label_2;
	private JLabel label_3;
	private JPanel left_panel;
	private JButton buttonCancel;
	private JPanel main_panel;
	private JSplitPane splitPane;
	private JPanel button_panel;
	private JButton buttonExport;
	private JButton buttonImport;
	private JPanel jtable_panel;
	private JPanel header_panel;
	private JLabel lblNewLabel_1;
	private JScrollPane scrollPane_1;
	private JCheckBox chckbxNewCheckBox;
	private JComboBox<Object> comboBox;
	private JComboBox<Object> comboBox_1;
	private JCheckBox chckbxNewCheckBox_1;
	private JCheckBox checkBox_1;
	private JCheckBox checkBox_3;
	private JCheckBox checkBox_4;
	private JCheckBox checkBox_5;
	private JCheckBox checkBox_6;
	private JCheckBox checkBox_7;
	private JCheckBox checkBox_8;
	private JCheckBox checkBox_9;
	private JCheckBox checkBox_10;
	private JCheckBox checkBox_11;
	private JCheckBox checkBox_12;
	private JCheckBox checkBox_13;
	private JCheckBox checkBox_14;
	private JCheckBox checkBox_15;
	private JCheckBox checkBox_16;
	private JCheckBox checkBox_17;
	private JCheckBox checkBox_18;
	private JCheckBox checkBox_19;
	private JCheckBox checkBox_20;
	private JCheckBox checkBox_21;
	private JCheckBox checkBox_22;
	private JCheckBox checkBox_23;
	private JCheckBox checkBox_24;
	private JCheckBox checkBox_25;
	private JCheckBox checkBox_26;
	private JCheckBox checkBox_27;
	private JCheckBox checkBox_28;
	JPanel panel_2;
	private PluginQueueTableModel pluginModel;
	public JCheckBox checkBox;
	JPanel scannerPanel;

	private PrintWriter stdout;
	private PrintWriter stderr;

	IBurpExtenderCallbacks callbacks;
	IExtensionHelpers helpers;

	BurpExtender plugin_ref;

	ConfigurationTableModel configurationModel;

	List<Configuration> ConfigurationList;
	List<PluginQueue> queueList;

	JCheckBox checkBox_2;

	public PluginGUI(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, BurpExtender plugin_ref,
			PluginQueueTableModel model1, ConfigurationTableModel model, List<Configuration> ConfigurationList,
			List<PluginQueue> QueueList, PrintWriter stdout, PrintWriter stderr) {
		this.callbacks = callbacks;
		this.helpers = helpers;
		this.plugin_ref = plugin_ref;
		this.pluginModel = model1;
		this.configurationModel = model;
		this.ConfigurationList = ConfigurationList;
		this.queueList = QueueList;
		this.stdout = stdout;
		this.stderr = stderr;
	}

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	public void run() {

		mainPanel = new JTabbedPane();

		// Initialize a empy panel to include in Burp Tab
		scannerPanel = new JPanel();
		configurationPanel = new JPanel();

		scannerPanel.setLayout(new BorderLayout(0, 0));

		left_panel = new JPanel();
		scannerPanel.add(left_panel, BorderLayout.SOUTH);

		buttonCancel = new JButton("Cancel all scans");
		buttonCancel.addActionListener(this);

		JButton buttonRemove = new JButton("Remove completed");
		buttonRemove.addActionListener(this);

		GroupLayout gl_left_panel = new GroupLayout(left_panel);
		gl_left_panel.setHorizontalGroup(gl_left_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_left_panel.createSequentialGroup().addContainerGap().addComponent(buttonCancel)
						.addPreferredGap(ComponentPlacement.RELATED).addComponent(buttonRemove).addContainerGap(15,
								Short.MAX_VALUE)));
		gl_left_panel.setVerticalGroup(gl_left_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_left_panel.createSequentialGroup().addContainerGap().addGroup(gl_left_panel
						.createParallelGroup(Alignment.BASELINE).addComponent(buttonCancel).addComponent(buttonRemove))
						.addGap(20)));
		left_panel.setLayout(gl_left_panel);

		main_panel = new JPanel();
		scannerPanel.add(main_panel, BorderLayout.CENTER);

		main_panel.setLayout(new BorderLayout(0, 0));

		table = new JTable(pluginModel);

		table.getColumnModel().getColumn(0).setPreferredWidth(60);
		table.getColumnModel().getColumn(0).setMinWidth(20);
		table.getColumnModel().getColumn(0).setMaxWidth(90);
		table.getColumnModel().getColumn(1).setPreferredWidth(300);
		table.getColumnModel().getColumn(1).setMinWidth(20);
		table.getColumnModel().getColumn(1).setMaxWidth(300);
		table.getColumnModel().getColumn(3).setPreferredWidth(150);
		table.getColumnModel().getColumn(3).setMinWidth(20);
		table.getColumnModel().getColumn(3).setMaxWidth(150);
		table.getColumnModel().getColumn(4).setPreferredWidth(90);
		table.getColumnModel().getColumn(4).setMinWidth(20);
		table.getColumnModel().getColumn(4).setMaxWidth(90);

		main_panel.add(new JScrollPane(table));

		configurationPanel.setLayout(new BorderLayout(0, 0));

		splitPane = new JSplitPane();
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);

		configurationPanel.add(splitPane, BorderLayout.CENTER);

		scan_profiles_panel = new JPanel();
		splitPane.setLeftComponent(scan_profiles_panel);

		buttonAdd = new JButton("Add");
		scan_profiles_panel.setLayout(new BorderLayout(0, 0));

		buttonDelete = new JButton("Delete");

		button_panel = new JPanel();
		scan_profiles_panel.add(button_panel, BorderLayout.WEST);

		buttonExport = new JButton("Export conf.");
		buttonExport.addActionListener(this);

		buttonImport = new JButton("Import conf.");
		buttonImport.addActionListener(this);

		GroupLayout gl_button_panel = new GroupLayout(button_panel);
		gl_button_panel.setHorizontalGroup(gl_button_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_button_panel.createSequentialGroup().addContainerGap().addGroup(gl_button_panel
						.createParallelGroup(Alignment.TRAILING, false)
						.addComponent(buttonDelete, Alignment.LEADING, GroupLayout.DEFAULT_SIZE,
								GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(buttonAdd, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 93, Short.MAX_VALUE)
						.addComponent(buttonExport, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE)
						.addComponent(buttonImport, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 74, Short.MAX_VALUE))
						.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
				.addGroup(Alignment.TRAILING,
						gl_button_panel.createSequentialGroup().addContainerGap(14, Short.MAX_VALUE)

								.addContainerGap()));
		gl_button_panel.setVerticalGroup(gl_button_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_button_panel.createSequentialGroup().addGap(10).addComponent(buttonAdd)
						.addPreferredGap(ComponentPlacement.RELATED).addComponent(buttonDelete)
						.addPreferredGap(ComponentPlacement.RELATED).addComponent(buttonExport)
						.addPreferredGap(ComponentPlacement.RELATED).addComponent(buttonImport)
						.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		button_panel.setLayout(gl_button_panel);

		scan_profile_table = new JTable(configurationModel);

		scan_profile_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		scan_profile_table.getColumnModel().getColumn(0).setPreferredWidth(60);
		scan_profile_table.getColumnModel().getColumn(1).setPreferredWidth(300);

		jtable_panel = new JPanel();
		jtable_panel.setBorder(null);

		scrollPane = new JScrollPane(scan_profile_table);
		jtable_panel.setLayout(new BorderLayout(0, 0));
		jtable_panel.add(scrollPane, BorderLayout.CENTER);

		scan_profiles_panel.add(jtable_panel, BorderLayout.CENTER);

		header_panel = new JPanel();
		scan_profiles_panel.add(header_panel, BorderLayout.NORTH);

		lblNewLabel_1 = new JLabel("Scan profiles");

		lblNewLabel_1.setForeground(new Color(228, 136, 56));
		Font f = lblNewLabel_1.getFont();
		lblNewLabel_1.setFont(f.deriveFont(f.getStyle() | Font.BOLD));
		f = lblNewLabel_1.getFont();
		lblNewLabel_1.setFont(f.deriveFont((float) (f.getSize() + 2)));

		GroupLayout gl_header_panel = new GroupLayout(header_panel);
		gl_header_panel.setHorizontalGroup(gl_header_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_header_panel.createSequentialGroup().addGap(5).addComponent(lblNewLabel_1)));
		gl_header_panel.setVerticalGroup(gl_header_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_header_panel.createSequentialGroup().addGap(5).addComponent(lblNewLabel_1).addGap(10)));
		header_panel.setLayout(gl_header_panel);

		// add the custom tab to Burp's UI
		mainPanel.addTab("Scanner", scannerPanel);
		mainPanel.addTab("Configuration", configurationPanel);

		active_configurator_panel = new JPanel();
		splitPane.setRightComponent(active_configurator_panel);
		active_configurator_panel.setLayout(new BorderLayout(0, 0));

		scrollPane_1 = new JScrollPane();
		active_configurator_panel.add(scrollPane_1, BorderLayout.CENTER);

		panel_2 = new JPanel();

		scrollPane_1.setViewportView(panel_2);
		lblNewLabel = new JLabel("Active Scanning Optimization");
		lblNewLabel.setForeground(new Color(228, 136, 56));
		Font font1 = lblNewLabel.getFont();
		lblNewLabel.setFont(font1.deriveFont(font1.getStyle() | Font.BOLD));
		font1 = lblNewLabel.getFont();
		lblNewLabel.setFont(font1.deriveFont((float) (font1.getSize() + 2)));

		label_1 = new JLabel("Active Scanning Areas");
		label_1.setForeground(new Color(228, 136, 56));
		font1 = label_1.getFont();
		label_1.setFont(font1.deriveFont(font1.getStyle() | Font.BOLD));
		font1 = label_1.getFont();
		label_1.setFont(font1.deriveFont((float) (font1.getSize() + 2)));

		label_2 = new JLabel("Scan speed:");

		label_3 = new JLabel("Scan accuracy:");

		chckbxNewCheckBox = new JCheckBox("Use intelligent attack selection");
		chckbxNewCheckBox.setName("intelligent_attack_selection");

		String[] speed_text = new String[] { "Fast", "Normal", "Thorough" };
		String[] accuracy_text = new String[] { "Minimize false genatives", "Normal", "Minimize false positives" };

		comboBox = new JComboBox<Object>(speed_text);
		comboBox.setName("scan_speed");
		comboBox_1 = new JComboBox<Object>(accuracy_text);
		comboBox_1.setName("scan_accuracy");

		chckbxNewCheckBox_1 = new JCheckBox("SQL Injection");
		chckbxNewCheckBox_1.setName("sql_injection+enabled");
		chckbxNewCheckBox_1.setSelected(true);

		checkBox = new JCheckBox("Error-based");
		checkBox.setName("sql_injection+error_based_checks");
		checkBox_1 = new JCheckBox("Time-delay checks");
		checkBox_1.setName("sql_injection+time_delay_checks");
		checkBox_2 = new JCheckBox("Boolen condition checks");
		checkBox_2.setName("sql_injection+boolean_condition_checks");
		checkBox_3 = new JCheckBox("MSSQL-specific checks");
		checkBox_3.setName("sql_injection+mssql_checks");
		checkBox_4 = new JCheckBox("Oracle-specific checks");
		checkBox_4.setName("sql_injection+oracle_checks");
		checkBox_5 = new JCheckBox("MySQL-specific checks");
		checkBox_5.setName("sql_injection+mysql_checks");
		checkBox_6 = new JCheckBox("OS Injection");
		checkBox_6.setSelected(true);

		checkBox_6.setName("os_command_injection+enabled");
		checkBox_7 = new JCheckBox("Informed");
		checkBox_7.setName("os_command_injection+informed_checks");
		checkBox_8 = new JCheckBox("Blind");
		checkBox_8.setName("os_command_injection+blind_checks");
		checkBox_9 = new JCheckBox("Server-side code injection");
		checkBox_9.setName("server_side_code_injection");
		checkBox_10 = new JCheckBox("Server-side template injection");
		checkBox_10.setName("server_side_template_injection");
		checkBox_11 = new JCheckBox("Reflected cross-site scripting");
		checkBox_11.setName("reflected_xss");
		checkBox_12 = new JCheckBox("Stored cross-site scripting");
		checkBox_12.setName("stored_xss");
		checkBox_13 = new JCheckBox("Reflected DOM issues");
		checkBox_13.setName("reflected_dom_issues");
		checkBox_14 = new JCheckBox("Stored DOM issues");
		checkBox_14.setName("stored_dom_issues");
		checkBox_15 = new JCheckBox("File path traversal / manipulation");
		checkBox_15.setName("file_path_traversal");
		checkBox_16 = new JCheckBox("External / out-of-band interaction");
		checkBox_16.setName("external_interaction");
		checkBox_17 = new JCheckBox("HTTP header injection");
		checkBox_17.setName("http_header_injection");
		checkBox_18 = new JCheckBox("SMTP header injection");
		checkBox_18.setName("smtp_header_injection");
		checkBox_19 = new JCheckBox("XML / SOAP injection");
		checkBox_19.setName("xml_soap_injection");
		checkBox_20 = new JCheckBox("LDAP injection");
		checkBox_20.setName("ldap_injection");
		checkBox_21 = new JCheckBox("Cross-site request forgery");
		checkBox_21.setName("csrf");
		checkBox_22 = new JCheckBox("Open redirection");
		checkBox_22.setName("open_redirection");
		checkBox_23 = new JCheckBox("Header manipulation");
		checkBox_23.setName("header_manipulation");
		checkBox_24 = new JCheckBox("Server-level issues");
		checkBox_24.setName("server_level_issues");
		checkBox_25 = new JCheckBox("Suspicious input transformation");
		checkBox_25.setName("suspicious_input_transformation");
		checkBox_26 = new JCheckBox("Input returned in response (reflected)");
		checkBox_26.setName("input_retrieval_reflected");
		checkBox_27 = new JCheckBox("Input returned in response (stored)");
		checkBox_27.setName("input_retrieval_stored");
		checkBox_28 = new JCheckBox("Link manipulation");
		checkBox_28.setName("link_manipulation");

		GroupLayout gl_panel_2 = new GroupLayout(panel_2);
		gl_panel_2.setHorizontalGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup().addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_2.createSequentialGroup().addContainerGap().addComponent(lblNewLabel))
						.addGroup(gl_panel_2.createSequentialGroup().addGap(22)
								.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING).addComponent(checkBox_6)
										.addComponent(chckbxNewCheckBox_1).addComponent(checkBox_9)
										.addComponent(checkBox_10).addComponent(checkBox_11).addComponent(checkBox_12)
										.addComponent(checkBox_13).addComponent(checkBox_14).addComponent(checkBox_15)
										.addComponent(checkBox_16).addComponent(checkBox_17).addComponent(checkBox_18)
										.addComponent(checkBox_19).addComponent(checkBox_20).addComponent(checkBox_21)
										.addComponent(checkBox_22).addComponent(checkBox_23).addComponent(checkBox_24)
										.addComponent(checkBox_25).addComponent(checkBox_28).addComponent(checkBox_26)
										.addComponent(checkBox_27)))
						.addGroup(gl_panel_2.createSequentialGroup().addGap(72).addComponent(checkBox_7))
						.addGroup(gl_panel_2.createSequentialGroup().addGap(66)
								.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING).addComponent(checkBox)
										.addComponent(checkBox_1).addGroup(
												gl_panel_2.createSequentialGroup().addComponent(checkBox_2).addGap(18)
														.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
																.addComponent(checkBox_4).addComponent(checkBox_5)
																.addComponent(checkBox_3).addComponent(checkBox_8)))))
						.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING, false)
								.addGroup(gl_panel_2.createSequentialGroup().addContainerGap().addComponent(label_1,
										GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addGroup(
										gl_panel_2.createSequentialGroup().addGap(22).addGroup(gl_panel_2
												.createParallelGroup(Alignment.LEADING).addGroup(gl_panel_2
														.createSequentialGroup()
														.addGroup(gl_panel_2
																.createParallelGroup(Alignment.TRAILING, false)
																.addComponent(label_2, GroupLayout.DEFAULT_SIZE,
																		GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
																.addComponent(label_3, GroupLayout.DEFAULT_SIZE, 82,
																		Short.MAX_VALUE))
														.addPreferredGap(ComponentPlacement.RELATED)
														.addGroup(gl_panel_2
																.createParallelGroup(Alignment.LEADING, false)
																.addComponent(comboBox_1, 0, GroupLayout.DEFAULT_SIZE,
																		Short.MAX_VALUE)
																.addComponent(comboBox, 0, 69, Short.MAX_VALUE)))
												.addComponent(chckbxNewCheckBox)))))
						.addContainerGap(484, Short.MAX_VALUE)));
		gl_panel_2.setVerticalGroup(gl_panel_2.createParallelGroup(Alignment.LEADING).addGroup(gl_panel_2
				.createSequentialGroup().addContainerGap().addComponent(lblNewLabel).addGap(18)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(label_2).addComponent(
						comboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(label_3).addComponent(
						comboBox_1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(ComponentPlacement.UNRELATED).addComponent(chckbxNewCheckBox).addGap(18)
				.addComponent(label_1).addGap(18).addComponent(chckbxNewCheckBox_1)
				.addPreferredGap(ComponentPlacement.UNRELATED)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(checkBox)
						.addComponent(checkBox_3))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(checkBox_1)
						.addComponent(checkBox_4))
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(checkBox_2)
						.addComponent(checkBox_5))
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_6)
				.addPreferredGap(ComponentPlacement.RELATED)
				.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE).addComponent(checkBox_7)
						.addComponent(checkBox_8))
				.addPreferredGap(ComponentPlacement.UNRELATED).addComponent(checkBox_9)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_10)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_11)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_12)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_13)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_14)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_15)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_16)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_17)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_18)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_19)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_20)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_21)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_22)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_23)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_24)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_25)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_28)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_26)
				.addPreferredGap(ComponentPlacement.RELATED).addComponent(checkBox_27).addGap(20)));
		panel_2.setLayout(gl_panel_2);

		// scan_profile_table.setRowSelectionAllowed(rowSelectionAllowed);
		scan_profile_table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

		// Load configuration from preferences or create a default
		if (callbacks.loadExtensionSetting("configuration_list") != null) {
			// Load configuration
			plugin_ref.load_configuration_from_preferences();

		} else {
			// Create default configuration and save it
			Configuration row1 = new Configuration(true, "Default", plugin_ref.json_configuration);
			ConfigurationList.add(row1);
			plugin_ref.save_configuration_to_preferences();
		}

		scan_profile_table.setRowSelectionInterval(0, 0);

		plugin_ref.update_ui_from_json(ConfigurationList.get(0).getConfiguration().toString());

		// Update the UI based on selected item
		ListSelectionModel selectionModel = scan_profile_table.getSelectionModel();
		selectionModel.addListSelectionListener(this);

		// Create automatically action listeners that save the
		// configuration on changes

		panel_2.setName("config_panel");

		Component[] allComponents = panel_2.getComponents();
		for (int i = 0; i < allComponents.length; i++) {
			if (allComponents[i].getName() == null)
				continue;

			if (allComponents[i] instanceof JCheckBox) {

				((JCheckBox) allComponents[i]).addItemListener(this);

			} else if (allComponents[i] instanceof JComboBox) {

				((JComboBox<?>) allComponents[i]).addItemListener(this);
			}

		}

		// Enable or disable sub options (SQL injections)
		chckbxNewCheckBox_1.addItemListener(this);

		// Enable or disable sub options (OS Injections)
		checkBox_6.addItemListener(this);

		buttonDelete.addActionListener(this);
		buttonAdd.addActionListener(this);

	}

	public void update_scanner_table(String action, int first_row, int last_row) {

		switch (action) {

		case "insert":
			pluginModel.fireTableRowsInserted(first_row, last_row);
			break;
		case "modify":
			pluginModel.fireTableRowsUpdated(first_row, last_row);
			break;
		case "delete":
			pluginModel.fireTableRowsDeleted(first_row, last_row);
			break;
		default:
			stdout.println("ERROR: wrong action on update swing");
			break;
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {

		if (e.getSource() instanceof JButton) {
			String srcText = ((JButton) e.getSource()).getText();
			stdout.println(srcText);

			switch (((JButton) e.getSource()).getText()) {

			// Remove button listener
			case "Delete":
				int cur_row = scan_profile_table.getSelectedRow();

				// Don't allow to remove default scan configuration
				if (cur_row != 0) {

					ConfigurationList.remove(cur_row);

					javax.swing.SwingUtilities.invokeLater(new Runnable() {
						public void run() {

							scan_profile_table.setRowSelectionInterval(cur_row - 1, cur_row - 1);
							configurationModel.fireTableRowsDeleted(cur_row, cur_row);

						}
					});

					plugin_ref.save_configuration_to_preferences();
				}

				break;

			// Add button listener
			case "Add":
				Configuration row2 = new Configuration(true, "User defined " + scan_profile_table.getRowCount(),
						plugin_ref.json_configuration);
				ConfigurationList.add(row2);

				javax.swing.SwingUtilities.invokeLater(new Runnable() {
					public void run() {

						configurationModel.fireTableRowsInserted(ConfigurationList.size() - 1,
								ConfigurationList.size() - 1);

						scan_profile_table.setRowSelectionInterval(scan_profile_table.getRowCount() - 1,

								scan_profile_table.getRowCount() - 1);
						scan_profile_table.scrollRectToVisible(
								scan_profile_table.getCellRect(scan_profile_table.getRowCount() - 1, 0, true));

					}

				});

				plugin_ref.save_configuration_to_preferences();
				break;

			case "Export conf.":
				exportToFile();
				break;

			case "Import conf.":
				importFromFile();
				break;

			case "Cancel all scans":

				for (int i = 0; i < queueList.size(); i++) {

					queueList.get(i).getBurpQueue().cancel();
				}

				break;

			case "Remove completed":

				for (int i = 0; i < queueList.size(); i++) {
					if (queueList.get(i).getBurpQueue().getStatus().contains("finished")
							|| queueList.get(i).getBurpQueue().getStatus().contains("cancelled")) {
						queueList.remove(i);

					}
				}

				break;

			}

		}

	}

	public void exportToFile() {
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration output file");

		int userSelection = fileChooser.showSaveDialog(parentFrame);

		if (userSelection == JFileChooser.APPROVE_OPTION) {

			File outputFile = fileChooser.getSelectedFile();
			FileWriter fw;
			try {
				fw = new FileWriter(outputFile);

				JSONObject all_conf = new JSONObject();

				for (int i = 0; i < ConfigurationList.size(); i++) {
					all_conf.put(Integer.toString(i), ConfigurationList.get(i).exportToJson());
				}

				fw.write(all_conf.toString());
				fw.close();

			} catch (IOException e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
				return;
			}

		}
	}

	public void importFromFile() {
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration input file");

		int userSelection = fileChooser.showOpenDialog(parentFrame);

		if (userSelection == JFileChooser.APPROVE_OPTION) {

			File inputFile = fileChooser.getSelectedFile();

			try {

				File file = new File(inputFile.toString());
				FileInputStream fis = new FileInputStream(file);
				byte[] data = new byte[(int) file.length()];
				fis.read(data);
				fis.close();

				JSONObject all_conf = new JSONObject(new String(data));

				Iterator<?> keys = all_conf.keys();

				ConfigurationList.clear();

				while (keys.hasNext()) {
					String key = (String) keys.next();

					Configuration row1 = new Configuration();
					row1.importFromJson(all_conf.getJSONObject(key).toString());
					ConfigurationList.add(row1);

				}

			} catch (Exception e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
				return;
			}

		}

	}

	@Override
	public void valueChanged(ListSelectionEvent arg0) {
		int cur_row = scan_profile_table.getSelectedRow();
		plugin_ref.update_ui_from_json(ConfigurationList.get(cur_row).getConfiguration().toString());
	}

	@Override
	public void itemStateChanged(ItemEvent e) {

		if (e.getSource() instanceof JCheckBox) {

			// Checkbox on config panel
			if (((JCheckBox) e.getSource()).getParent().getName() == "config_panel") {
				int cur_row = scan_profile_table.getSelectedRow();

				ConfigurationList.get(cur_row).setConfiguration(plugin_ref.build_json_from_ui().toString());
				plugin_ref.save_configuration_to_preferences();

			}

			// XXX BUG: if in default configuration the SQL injection or command
			// execution family is deselected
			// the child are not blocked after a plugin reload

			// Automatic grey some choices
			if (((JCheckBox) e.getSource()).getName() == "sql_injection+enabled") {

				if (e.getStateChange() == ItemEvent.DESELECTED) {
					checkBox.setEnabled(false);
					checkBox_1.setEnabled(false);
					checkBox_2.setEnabled(false);
					checkBox_3.setEnabled(false);
					checkBox_4.setEnabled(false);
					checkBox_5.setEnabled(false);
				} else {
					checkBox.setEnabled(true);
					checkBox_1.setEnabled(true);
					checkBox_2.setEnabled(true);
					checkBox_3.setEnabled(true);
					checkBox_4.setEnabled(true);
					checkBox_5.setEnabled(true);

				}
			} else if (((JCheckBox) e.getSource()).getName() == "os_command_injection+enabled") {

				if (e.getStateChange() == ItemEvent.DESELECTED) {

					checkBox_7.setEnabled(false);
					checkBox_8.setEnabled(false);
				} else {
					checkBox_7.setEnabled(true);
					checkBox_8.setEnabled(true);

				}
			}

		}

		else if (e.getSource() instanceof JComboBox) {

			// ComboBox on config panel
			if (((JComboBox<?>) e.getSource()).getParent().getName() == "config_panel") {

				// Save json on preferences when a ComboBox is changed

				int cur_row = scan_profile_table.getSelectedRow();

				if (e.getStateChange() == ItemEvent.SELECTED) {
					ConfigurationList.get(cur_row).setConfiguration(plugin_ref.build_json_from_ui().toString());
					plugin_ref.save_configuration_to_preferences();

				}

			}

		}
	}
}
