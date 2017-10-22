/*****************************************************************************
 * ScannerThread.java part of AttackSelector Burp Plugin                     *
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

import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import org.json.JSONObject;

public class ScannerThread implements Runnable {

	BurpExtender burp_plugin;

	private List<PluginQueue> queueList;
	private ReentrantLock lock;
	private static PrintWriter stdout;

	// Thread will check new work every X milliseconds
	private int check_every = 2000;

	private volatile boolean running = true;

	private IBurpExtenderCallbacks callbacks;

	public ScannerThread(BurpExtender plugin_ref) {

		burp_plugin = plugin_ref;

		queueList = burp_plugin.getqueueList();
		lock = burp_plugin.getLock();
		stdout = burp_plugin.getStdout();
		callbacks = burp_plugin.getCallbacks();
	}

	public void terminate() {
		running = false;
	}

	@Override
	public void run() {

		int maxThreads;

		while (running) {

			try {

				// Get current maximum of threads
				String jsonConfig = callbacks.saveConfigAsJson();
				JSONObject obj = new JSONObject(jsonConfig);
				maxThreads = obj.getJSONObject("scanner").getJSONObject("active_scanning_engine")
						.getInt("number_of_threads");

				lock.lock();
				try {

					int currentThreads = 0;
					int configuration = -1;
					int thread_change = -1;

					// Removed unused threads
					for (int i = 0; i < queueList.size(); i++) {

						if (queueList.get(i).getStatus() == 1) {

							if (queueList.get(i).getBurpQueue().getStatus().contains("complete")) {

								// Save current running configuration
								configuration = queueList.get(i).getConfiguration();
								currentThreads++;

							} else if (queueList.get(i).getBurpQueue().getStatus().contains("finished")) {
								queueList.get(i).setStatus(2);
								thread_change = 0;
							}

							else if (queueList.get(i).getBurpQueue().getStatus().contains("cancelled")) {
								queueList.get(i).setStatus(3);
								thread_change = 0;
							}

						}
					}

					// Revert configuration to default when all scan has been
					// finished
					if (thread_change == 0)
						burp_plugin.updateScannerConfig(queueList.get(0).getConfiguration());

					// Add same configuration works
					for (int i = 0; i < queueList.size(); i++) {

						// If threads are full just skip
						if (currentThreads > maxThreads)
							break;

						if (queueList.get(i).getStatus() == 0) {

							if (queueList.get(i).getStatus() == 0
									&& configuration == queueList.get(i).getConfiguration()) {

								if (currentThreads < maxThreads) {

									stdout.println("Add same configuration");

									// Update to running
									queueList.get(i).setStatus(1);

									// Request to burp to scan the URL and
									// save the scan queue
									queueList.get(i).setBurpQueue(burp_plugin.scanVuln(queueList.get(i).getMessage(),
											queueList.get(i).getIntruder()));

									currentThreads++;

									stdout.println("Added a new URL to SCAN");

								}
							}
						}
					}

					// Add new work if all threads are free
					for (int i = 0; i < queueList.size(); i++) {

						// If threads are full just skip
						if (currentThreads > maxThreads)
							break;

						if (queueList.get(i).getStatus() == 0) {

							if (configuration == -1) {

								configuration = queueList.get(i).getConfiguration();
								burp_plugin.updateScannerConfig(configuration);

							} else if (configuration != queueList.get(i).getConfiguration())
								continue;

							if (currentThreads < maxThreads) {

								// Update to running
								queueList.get(i).setStatus(1);

								// Request to burp to scan the URL and save the
								// scan queue
								queueList.get(i).setBurpQueue(burp_plugin.scanVuln(queueList.get(i).getMessage(),
										queueList.get(i).getIntruder()));

								currentThreads++;
							}

						}
					}

				} finally {
					lock.unlock();
				}

				// wait sometimes, we do not want to use 100% of the CPU
				Thread.sleep(check_every);

			} catch (InterruptedException e) {

				stdout.println("Thread interrupted");
			}
		}

		stdout.println("Thread ended.");
	}
}
