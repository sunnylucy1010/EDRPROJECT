# Bkedr Server

## Prerequisites
Before you continue, ensure you meet the following requirements:
 
- You have installed the latest version of Golang.
- You are using a Linux or Mac OS machine. Windows is not currently supported.
- You have install the Universal Forwarder on Linux
- The Splunk Server

## Install Universal Forwarder on Linux

- The universal forwarder is available for Linux as a tar file, an RPM package, and a DEB package.
- In my case, I install from a tar file.
- To install the forwarder into the folder /opt/splunkforwarder, run:

```
tar xvzf splunkforwarder-<…>-Linux-x86_64.tgz -C /opt
```

## Install bkedr Server
- Download source code from github https://github.com/sunnylucy1010/EDRPROJECT/
- Create directory configs and file server.conf
- Run install.sh file as sudo
```
git clone https://github.com/jinjimosd/bkedr.git
cd bkedr
mkdir configs
vim configs/server.conf

{
  "ServerConfig": [
    {
      "ParentDirPath":"./downloadfile",
      "ResultLogPath":"./log/responselog.txt",
      "RuleFilePath":"./rules/responserules.txt",
      "AppLogPath":"./log/applog.txt",
      "AgentsConfPath":"./configs/agents.conf",
      "SplunkHost":"<Splunk server host>",
      "ServerHost":"<bkedr server host>",
      "ServerPort":"10000"
    }
  ]
}

chmod +x install.sh
sudo ./install.sh
```
## Configure Universal Forwarder on Linux
- Configure the universal forwarder to send data to the Splunk Enterprise indexer 

- From a shell prompt on the universal forwarder, go to the */opt/splunkforwarder/bin* directory.
```
cd /opt/splunkforwarder/bin
```

- Specify the host name or ip address of the Splunk Enterprise receiver.
```
./splunk add forward-server <host>:<port>
```

- Configure the universal forwarder as a deployment client.
```
./splunk set deploy-poll <host>:<port>
```

- Create file /opt/splunkforwarder/etc/system/local/inputs.conf and add below lines.
```
vim /opt/splunkforwarder/etc/system/local/inputs.conf

[monitor:///opt/bkedr/log/resultlog.txt]
disabled = false
index = responselog
```
- Edit file /opt/splunkforwarder/etc/system/local/deploymentclient.conf 
```
vim /opt/splunkforwarder/etc/system/local/deploymentclient.conf 

[target-broker:deploymentServer]
targetUri = <host>:<port>
```

### Start server
```
sudo systemctl start bkedr.services
```
### Start Splunk Forwarder
```
sudo /opt/splunkforwarder/bin/splunk start
```

# Installing bkedr agent.
- Download source code from github https://github.com/jinjimosd/bkedr.git
- Create windowsagent.conf and add config.

```
{
  "AgentConfig": [
    {
      "AdapterInternet":"<Name Of Network Adapter>",
      "ServerHost":"<bkedr Server Host>",
      "ServerPort":"10000",
      "AgentHost":"<Agent Host>",
      "AgentPort":"1234"
    }
  ]
}
```
- Go to C:\Windows\System32 and create bkedrAgent directory
- Copy bkedragent.exe and windowsagent.conf to bkedrAgent directory 
- Run Windows PowerShell as Administrator and run command
```
sc.exe create bkedragent binPath= "C:\Windows\System32\BkedrAgent\bkedragent.exe" DisplayName= "Bkedr Agent" start= auto
sc.exe start bkedragent
```
## ⛏️ Changelog <a name = "Changelog">Changelog</a>

- Update name cmd
- Update delete EventCode7

## ⛏️ Built Using <a name = "built_using"></a>

- [Golang](https://golang.org/) - Main Code Language
- [GRPC](https://grpc.io/) - Open source high performance Remote Procedure Call
- [Protocol Buffer](https://developers.google.com/protocol-buffers) - Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data

## ✍️ Authors <a name = "authors"></a>
- Viettel Cyber Security team

## Reference
- ionstorm | Sysmon Based EDR written in PowerShell: https://github.com/ion-storm/sysmon-edr
- Olaf Hartong | sysmon-modular | A Sysmon configuration repository for everybody to customise: https://github.com/olafhartong/sysmon-modular
- Olaf Hartong | ThreatHunting | A Splunk app mapped to MITRE ATT&CK to guide your threat hunts: https://github.com/olafhartong/ThreatHunting
