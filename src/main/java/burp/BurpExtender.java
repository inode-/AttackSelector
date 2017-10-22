/*****************************************************************************
 * BurpExtender.java part of AttackSelector Burp Plugin                      *
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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JMenuItem;
import org.json.JSONObject;

import java.awt.Component;
import javax.swing.JMenu;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, ITab, IExtensionStateListener {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private PrintWriter stdout;
	private PrintWriter stderr;

	IHttpRequestResponse[] selectedMessage;
	static char insertionPointChar;

	PluginGUI pluginGUI;

	JPanel configurationPanel;

	// JTable lists
	private List<Configuration> ConfigurationList;
	private List<PluginQueue> queueList;
	private PluginQueueTableModel queueModel;
	private ConfigurationTableModel configurationModel;

	// Threads objects
	private ReentrantLock lock;
	private Thread running_thread;
	private ScannerThread scannerThread = null;

	// Default burp configuration
	String json_configuration = new String(
			"{\"scanner\":{ \"active_scanning_areas\":{  \"csrf\":true, \"link_manipulation\":true, \"external_interaction\":true,  \"file_path_traversal\":true,  \"header_manipulation\":true,  \"http_header_injection\":true,  \"input_retrieval_reflected\":false,  \"input_retrieval_stored\":false,  \"ldap_injection\":true,  \"open_redirection\":true,  \"os_command_injection\":{  \"blind_checks\":true,  \"enabled\":true,  \"informed_checks\":true  },  \"reflected_dom_issues\":true,  \"reflected_xss\":false,  \"server_level_issues\":true,  \"server_side_code_injection\":true,  \"server_side_template_injection\":true,  \"smtp_header_injection\":true,  \"sql_injection\":{  \"boolean_condition_checks\":true,  \"enabled\":true,  \"error_based_checks\":true,  \"mssql_checks\":true,  \"mysql_checks\":true,  \"oracle_checks\":true,  \"time_delay_checks\":true  },  \"stored_dom_issues\":true,  \"stored_xss\":true,  \"suspicious_input_transformation\":true,  \"xml_soap_injection\":true }, \"active_scanning_optimization\":{  \"intelligent_attack_selection\":true,  \"scan_accuracy\":\"normal\",  \"scan_speed\":\"normal\" }}}");

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

		// Keep a reference to our callbacks object
		this.callbacks = callbacks;

		// Obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// Set our extension name
		callbacks.setExtensionName("Attack Selector");

		// register to produce options for the context menu
		callbacks.registerContextMenuFactory(this);

		callbacks.registerExtensionStateListener(this);

		// Initialize stdout and stderr
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);

		stdout.println("Plugin loading...");

		ConfigurationList = new ArrayList<Configuration>();
		queueList = new ArrayList<PluginQueue>();

		insertionPointChar = (char) 167;

		lock = new ReentrantLock();

		queueModel = new PluginQueueTableModel(queueList, ConfigurationList, helpers);
		configurationModel = new ConfigurationTableModel(ConfigurationList);

		pluginGUI = new PluginGUI(callbacks, helpers, this, queueModel, configurationModel, ConfigurationList,
				queueList, stdout, stderr);

		try {
			SwingUtilities.invokeAndWait(pluginGUI);
		} catch (InvocationTargetException | InterruptedException e) {
			e.printStackTrace();
		}

		callbacks.customizeUiComponent(pluginGUI.scannerPanel);
		callbacks.addSuiteTab(BurpExtender.this);

		// Start queue manager thread
		scannerThread = new ScannerThread(this);
		running_thread = new Thread(scannerThread);
		running_thread.start();

		stdout.println("Attack selector loaded successfully.");

		// Used only for debugging purpose
		/*
		 * String jsonConfig = this.callbacks.saveConfigAsJson(); JSONObject obj
		 * = new JSONObject(jsonConfig);
		 * stdout.println(obj.getJSONObject("scanner").toString());
		 */

	}

	/**
	 * Save the configuration of the plugin to burp preferences
	 */
	public void save_configuration_to_preferences() {
		JSONObject all_conf = new JSONObject();

		for (int i = 0; i < ConfigurationList.size(); i++) {
			all_conf.put(Integer.toString(i), ConfigurationList.get(i).exportToJson());
		}

		callbacks.saveExtensionSetting("configuration_list", all_conf.toString());

	}

	/**
	 * Load plugin configuration from burp preferences
	 */
	public void load_configuration_from_preferences() {

		JSONObject all_conf = new JSONObject(callbacks.loadExtensionSetting("configuration_list"));

		Iterator<?> keys = all_conf.keys();

		while (keys.hasNext()) {
			String key = (String) keys.next();

			Configuration row1 = new Configuration();
			row1.importFromJson(all_conf.getJSONObject(key).toString());
			ConfigurationList.add(row1);

		}

		stdout.println("Configuration loaded.");

	}

	/**
	 * Create the JSON containings the values from the UI
	 */
	public JSONObject build_json_from_ui() {

		Component[] allComponents = pluginGUI.panel_2.getComponents();
		JSONObject obj = new JSONObject(json_configuration);

		// Parse active scanning optimization section
		JSONObject active_scanning_optimization = obj.getJSONObject("scanner")
				.getJSONObject("active_scanning_optimization");

		for (int i = 0; i < allComponents.length; i++) {
			if (allComponents[i].getName() == null)
				continue;

			if (allComponents[i].getName().equals("intelligent_attack_selection")) {

				JCheckBox button22 = (JCheckBox) allComponents[i];

				active_scanning_optimization.put("intelligent_attack_selection", button22.isSelected());

			} else if (allComponents[i].getName().equals("scan_accuracy")) {

				JComboBox<?> pluto = (JComboBox<?>) allComponents[i];

				switch (pluto.getSelectedIndex()) {
				case 0:
					active_scanning_optimization.put("scan_accuracy", "minimise_false_negatives");
					break;
				case 1:
					active_scanning_optimization.put("scan_accuracy", "normal");
					pluto.setSelectedIndex(1);
					break;
				case 2:
					active_scanning_optimization.put("scan_accuracy", "minimise_false_positives");
					pluto.setSelectedIndex(2);
					break;
				}

			} else if (allComponents[i].getName().equals("scan_speed")) {
				JComboBox<?> pluto = (JComboBox<?>) allComponents[i];

				switch (pluto.getSelectedIndex()) {
				case 0:
					active_scanning_optimization.put("scan_speed", "fast");
					break;
				case 1:
					active_scanning_optimization.put("scan_speed", "normal");
					break;
				case 2:
					active_scanning_optimization.put("scan_speed", "thorough");
					break;
				}

			}
		}

		// Parse active scanning areas section
		JSONObject attackInsertionPoitnsObject = obj.getJSONObject("scanner").getJSONObject("active_scanning_areas");

		Iterator<?> keys = attackInsertionPoitnsObject.keys();

		while (keys.hasNext()) {
			String key = (String) keys.next();

			if (attackInsertionPoitnsObject.get(key) instanceof JSONObject) {
				JSONObject child = (JSONObject) (attackInsertionPoitnsObject.get(key));
				Iterator<?> keys1 = child.keys();
				while (keys1.hasNext()) {
					String key1 = (String) keys1.next();

					for (int i = 0; i < allComponents.length; i++) {

						if (allComponents[i].getName() == null)
							continue;

						if (allComponents[i].getName().equals(key + '+' + key1)) {

							if (allComponents[i] instanceof JCheckBox) {
								JCheckBox button22 = (JCheckBox) allComponents[i];
								child.put(key1, button22.isSelected());

							}
						}
					}

				}

			} else {

				for (int i = 0; i < allComponents.length; i++) {

					if (allComponents[i].getName() == null)
						continue;

					if (allComponents[i].getName().equals(key)) {

						if (allComponents[i] instanceof JCheckBox) {
							JCheckBox button22 = (JCheckBox) allComponents[i];
							attackInsertionPoitnsObject.put(key, button22.isSelected());
						}
					}
				}
			}
		}

		return obj;
	}

	/**
	 * Update UI from a JSON containing the configuration
	 */
	public void update_ui_from_json(String json) {

		Component[] allComponents = pluginGUI.panel_2.getComponents();

		JSONObject obj = new JSONObject(json);

		JSONObject active_scanning_optimization = obj.getJSONObject("scanner")
				.getJSONObject("active_scanning_optimization");

		for (int i = 0; i < allComponents.length; i++) {
			if (allComponents[i].getName() == null)
				continue;

			if (allComponents[i].getName().equals("intelligent_attack_selection")) {

				JCheckBox button22 = (JCheckBox) allComponents[i];
				button22.setSelected((boolean) active_scanning_optimization.get("intelligent_attack_selection"));

			} else if (allComponents[i].getName().equals("scan_accuracy")) {

				JComboBox<?> pluto = (JComboBox<?>) allComponents[i];

				switch (active_scanning_optimization.get("scan_accuracy").toString()) {
				case "minimise_false_negatives":
					pluto.setSelectedIndex(0);
					break;
				case "normal":
					pluto.setSelectedIndex(1);
					break;
				case "minimise_false_positives":
					pluto.setSelectedIndex(2);
					break;
				}

			} else if (allComponents[i].getName().equals("scan_speed")) {
				JComboBox<?> pluto = (JComboBox<?>) allComponents[i];

				switch (active_scanning_optimization.get("scan_speed").toString()) {
				case "fast":
					pluto.setSelectedIndex(0);
					break;
				case "normal":
					pluto.setSelectedIndex(1);
					break;
				case "thorough":
					pluto.setSelectedIndex(2);
					break;
				}

			}
		}

		JSONObject attackInsertionPoitnsObject = obj.getJSONObject("scanner").getJSONObject("active_scanning_areas");

		Iterator<?> keys = attackInsertionPoitnsObject.keys();

		while (keys.hasNext()) {
			String key = (String) keys.next();

			if (attackInsertionPoitnsObject.get(key) instanceof JSONObject) {
				JSONObject child = (JSONObject) (attackInsertionPoitnsObject.get(key));
				Iterator<?> keys1 = child.keys();
				while (keys1.hasNext()) {
					String key1 = (String) keys1.next();

					for (int i = 0; i < allComponents.length; i++) {

						if (allComponents[i].getName() == null)
							continue;

						if (allComponents[i].getName().equals(key + '+' + key1)) {
							if (allComponents[i] instanceof JCheckBox) {
								JCheckBox button22 = (JCheckBox) allComponents[i];
								button22.setSelected((boolean) child.get(key1));
							}
						}
					}

				}

			} else {

				for (int i = 0; i < allComponents.length; i++) {

					if (allComponents[i].getName() == null)
						continue;

					if (allComponents[i].getName().equals(key)) {
						if (allComponents[i] instanceof JCheckBox) {
							JCheckBox button22 = (JCheckBox) allComponents[i];
							button22.setSelected((boolean) attackInsertionPoitnsObject.get(key));
						}
					}
				}
			}
		}

	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

		// Add custom content menu
		if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
				|| invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
				|| invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS
				|| invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY) {

			selectedMessage = invocation.getSelectedMessages();

			List<JMenuItem> menu = new ArrayList<JMenuItem>();

			JMenu main_menu = new JMenu("Attack selector");

			for (int i = 0; i < ConfigurationList.size(); i++) {
				if (ConfigurationList.get(i).getEnabled() == true) {
					JMenuItem men_item = new JMenuItem(ConfigurationList.get(i).getName());

					men_item.setActionCommand(Integer.toString(i + 1000));
					men_item.addActionListener(this);

					main_menu.add(men_item);
				}
			}

			menu.add(main_menu);

			return menu;

		} else {

			return null;
		}

	}

	/**
	 * Update burp scanner configuration with our needed option
	 * 
	 * @param configurationIndex
	 */
	public void updateScannerConfig(int configurationIndex) {

		// Read Burp config
		String jsonConfig = callbacks.saveConfigAsJson();

		// Parse Burp config and update the value of scanner parameters
		JSONObject obj = new JSONObject(jsonConfig);

		JSONObject current_config = obj.getJSONObject("scanner");

		// Update the configuration with our options
		current_config.put("active_scanning_areas", ConfigurationList.get(configurationIndex).exportToJson()
				.getJSONObject("configuration").getJSONObject("scanner").getJSONObject("active_scanning_areas"));
		current_config.put("active_scanning_optimization", ConfigurationList.get(configurationIndex).exportToJson()
				.getJSONObject("configuration").getJSONObject("scanner").getJSONObject("active_scanning_optimization"));

		// Load updated config
		callbacks.loadConfigFromJson(obj.toString());

	}

	/**
	 * Add to burp active scan by Federico Dotta
	 * 
	 * @param message
	 * @param intruder
	 * @return
	 */
	public IScanQueueItem scanVuln(IHttpRequestResponse message, boolean intruder) {

		IScanQueueItem ret;

		String requestString = new String(message.getRequest());

		List<int[]> insertionPointCoupledIndexes = new ArrayList<int[]>();
		int[] currentCouple = new int[2];

		if (intruder == true) {
			boolean first = true;
			int currentIndex = requestString.indexOf(insertionPointChar);
			if (currentIndex != -1) {
				currentCouple[0] = currentIndex;
				requestString = deleteCharAt(requestString, currentIndex);
				first = false;
			}
			while (currentIndex >= 0) {
				currentIndex = requestString.indexOf(insertionPointChar);
				if (currentIndex != -1 && first) {
					requestString = deleteCharAt(requestString, currentIndex);
					currentCouple[0] = currentIndex;
					first = false;
				} else if (currentIndex != -1 && !first) {
					requestString = deleteCharAt(requestString, currentIndex);
					currentCouple[1] = currentIndex - 1;
					first = true;
					insertionPointCoupledIndexes.add(currentCouple);
					currentCouple = new int[2];
				}

			}
		}

		if (intruder == true && insertionPointCoupledIndexes.size() > 0) {

			// Do active scan on selected insertion points
			ret = callbacks.doActiveScan(message.getHttpService().getHost(), message.getHttpService().getPort(),
					(message.getHttpService().getProtocol().equals("http") ? false : true), requestString.getBytes(),
					insertionPointCoupledIndexes);

		} else {

			// Do active scan on every insertion points
			ret = callbacks.doActiveScan(message.getHttpService().getHost(), message.getHttpService().getPort(),
					(message.getHttpService().getProtocol().equals("http") ? false : true), requestString.getBytes());

		}

		return ret;

	}

	public static String deleteCharAt(String s, int index) {

		StringBuilder sb = new StringBuilder(s);
		sb.deleteCharAt(index);
		return sb.toString();

	}

	@Override
	public void actionPerformed(ActionEvent event) {

		String command = event.getActionCommand();

		PluginQueue obj = new PluginQueue();
		obj.setMessage(selectedMessage[0]);

		obj.setQueueNumber(queueList.size());
		obj.setStatus(0);

		if (Integer.parseInt(command) >= 1000) {
			obj.setConfiguration(Integer.parseInt(command) - 1000);
			obj.setIntruder(false);
		} else {
			obj.setConfiguration(Integer.parseInt(command));
			obj.setIntruder(true);
		}

		lock.lock();
		try {
			queueList.add(obj);
		} finally {
			lock.unlock();
		}

		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				pluginGUI.update_scanner_table("insert", queueList.size() - 1, queueList.size() - 1);
			}
		});

	}

	public List<PluginQueue> getqueueList() {
		return queueList;
	}

	public ReentrantLock getLock() {
		return lock;

	}

	public PrintWriter getStdout() {
		return stdout;

	}

	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	/*
	 * This method return the name of the created tab
	 */
	@Override
	public String getTabCaption() {

		return "Attack selector";

	}

	/*
	 * This method return the panel that will be included in Burp Suite
	 */
	@Override
	public Component getUiComponent() {

		return pluginGUI.mainPanel;
	}

	@Override
	public void extensionUnloaded() {

		// Request to stop the thread in case of extension unload
		scannerThread.terminate();

	}
}
