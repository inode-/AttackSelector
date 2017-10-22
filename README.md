# Burp Attack Selector Plugin

During latest years Burp Suite scanner checks has been expanded a lot, but unfortunately the need of a scan time compromise has limited notably the checks executed during the scans with "Intelligent check" enabled. The current standard configuration will allow you to find the main issues but will not identify some kinds of problem. Also by modifiing the Burp configuration you will not be able to manage correctly the scans due [some actual Burp limitations](https://support.portswigger.net/customer/portal/questions/17025859-active-scan-configuration-taken-when-scan-request-insered-into-the-queue-and-not-when-scan-start).

This plugin will let you to configure different settings for Burp active scanner and create some custom scanner configuration that can be launched via menu. The plugin will automatically manage the new queue and run scans with the different configuration.

**Please note that when using this plugin you should NOT use the normal active scanner nor modify Burp scanning configuration**, by default the scanner will use the current configuration, so will execute only the tests configured in the running scan of this plugin. For this purpose we created a "default" scan configuration in this plugin that will allow you "simulate" the standard active scan, but it will be managed inside of the plugin so will be compatible with our others scans.

During last week I discovered that [Burp Developers are planning to add some new features](https://support.portswigger.net/customer/portal/questions/17162032-my-letter-to-santa-burp-team-2-17-extender-api-enhancements-) like the queue management, maybe in some month my plugin will be unuseful ;)

I have to thank [Federico Dotta](https://github.com/federicodotta/) for introducing me in Burp plugin programming and for the help given during the writing of this plugin.

## Usage

When the plugin is added to Burp Suite a new tab will apper. This tab will allow you to see the plugin queue and configure your custom scanner configuration. After that you will able to launch the scan with that configuration via the content menu created.

![Configuration screenshot](https://user-images.githubusercontent.com/4608466/31863359-f0e1bb48-b74c-11e7-8242-726498266d3a.png)

![Queue management screenshot](https://user-images.githubusercontent.com/4608466/31863384-52999748-b74d-11e7-98b7-2b2b6899bbb5.png)

![Custom menu in proxy history](https://user-images.githubusercontent.com/4608466/31863391-7404902c-b74d-11e7-937d-1d40591d46b9.png)

![Custom menu in intruder](https://user-images.githubusercontent.com/4608466/31863404-9c206e82-b74d-11e7-92b0-58bb0ba3a2df.png)

## License

Copyright (c) 2017, Agazzini Maurizio - inode@mediaservice.net            
All rights reserved.                                                      
                                                                          
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:                                                                  

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.       
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.                                                       
* Neither the name of @ Mediaservice.net nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.       
                                                                          
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.