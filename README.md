# ZipCheck
Step 1:
In Registry Editor, under the key:
HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\
add a new key called native_messaging_host, and native_messanging_host.json's absolute path as the value.

Step 2:
At line 7 of the native_messagging_host.json, insert your chrome extension ID.

Step 3:
At line 49 of the native_app.py, insert your VirusTotal API key.

Step 4:
Load the entire ZipCheck folder into Chrome Extensions.