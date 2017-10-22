/*****************************************************************************
 * Configuration.java part of AttackSelector Burp Plugin                     *
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

import org.json.JSONObject;

public class Configuration {

	private Boolean enabled;
	private String name;
	private JSONObject configuration;

	public Configuration() {

	}

	public Configuration(Boolean enabled, String name, String conf) {

		this.enabled = enabled;
		this.name = name;
		configuration = new JSONObject(conf);
	}

	public String getName() {
		return name;
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public JSONObject getConfiguration() {
		return configuration;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public void setConfiguration(String conf) {
		configuration = new JSONObject(conf);
	}

	public JSONObject exportToJson() {
		JSONObject obj;

		obj = new JSONObject();

		obj.put("name", name);
		obj.put("enabled", enabled);
		obj.put("configuration", configuration);

		return obj;
	}

	public void importFromJson(String conf) {
		JSONObject obj = new JSONObject(conf);

		setName((String) obj.get("name"));
		setEnabled((Boolean) obj.get("enabled"));

		configuration = new JSONObject(obj.getJSONObject("configuration").toString());

	}
}
