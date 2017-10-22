/*****************************************************************************
 * PluginQueue.java part of AttackSelector Burp Plugin                       *
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

public class PluginQueue {

	private int queueNumber;
	private IHttpRequestResponse message;
	private int configuration;
	private int status;
	private IScanQueueItem burp_queue;
	private boolean intruder;

	public int getQueueNumber() {
		return queueNumber;
	}

	public IHttpRequestResponse getMessage() {
		return message;
	}

	public int getConfiguration() {
		return configuration;
	}

	public int getStatus() {
		return status;
	}

	public boolean getIntruder() {
		return intruder;
	}

	public IScanQueueItem getBurpQueue() {
		return burp_queue;
	}

	public void setQueueNumber(int i) {
		queueNumber = i;
	}

	public void setIntruder(boolean i) {
		intruder = i;
	}

	public void setMessage(IHttpRequestResponse msg) {
		message = msg;
	}

	public void setConfiguration(int i) {
		configuration = i;
	}

	public void setStatus(int i) {
		status = i;
	}

	public void setBurpQueue(IScanQueueItem burp_queue) {
		this.burp_queue = burp_queue;
	}

}
