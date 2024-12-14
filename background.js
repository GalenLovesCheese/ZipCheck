chrome.downloads.onDeterminingFilename.addListener((downloadItem) => {
  // Pause the download temporarily
  chrome.downloads.pause(downloadItem.id, () => {
    // Connect to the native application
    var nativePort = chrome.runtime.connectNative("native_messaging_host");

    // Send the URL to the native application for download and scanning
    nativePort.postMessage({ action: 'download_and_scan', url: downloadItem.url });
    nativePort.onMessage.addListener((response) => {
      console.log("Response from native host:", response);
      if (response.status === 'success') {
        // Inform the user about the VirusTotal scan results
        const numFlags = response.flags;
        
        chrome.notifications.create('virus-scan-result', {
          type: 'basic',
          iconUrl: 'icon.png',
          title: 'Download Scan Result',
          message: `The file has ${numFlags} flags in the scan. Do you want to continue downloading?`,
          priority: 2,
          buttons: [
            { title: 'Yes' },
            { title: 'No' }
          ]
        });

        chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
          if (notificationId === 'virus-scan-result') {
            const userResponse = buttonIndex === 0; // `true` for 'Yes', `false` for 'No'
            console.log("User response:", userResponse);
            
            if (userResponse) {
              chrome.downloads.resume(downloadItem.id);
              console.log("User chose to proceed with the download.");
              // Perform actions to resume the download
            } else {
              chrome.downloads.cancel(downloadItem.id);
              console.log("User chose to cancel the download.");
              // Perform actions to cancel the download
            }
            chrome.notifications.clear(notificationId);
          }
        });

        nativePort.disconnect();
        setTimeout(() => {
          nativePort.disconnect();
          console.log("The native app did not respond in time. Cancelling download.");
          chrome.downloads.cancel(downloadItem.id); // Ensure download is canceled in case of timeout
        }, 10000); 
      }
    });
  });
});
