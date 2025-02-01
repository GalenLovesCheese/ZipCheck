# ZipCheck

A cybersecurity tool for checking security against file downloads in the browser.

## Description

A WIP cybersecurity tool that, as a Chrome extension, will intercept file downloads, break down downloaded file (e.g. decompress ZIP file) into original contents (and check for password protection and prompt for password for decryption if needed), check said contents against VirusTotal, and provides security rating information about said contents.

Made by Team WeLoveSigmas for Singapore's Div0's HackSmith V5.0 (cybersecurity tool hackathon).

## Authors

GitHub<br>
[@Danial Nurhakim](https://github.com/dnlnrkm)<br>
[@Galen Tay](https://github.com/GalenLovesCheese)<br>
[@Jie Xin](https://github.com/LuKaito1412)

## Instructions

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
