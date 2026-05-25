chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    console.log("Scanning:", tab.url);

    try {
      const response = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: tab.url,
        }),
      });

      const data = await response.json();

      console.log("SCAN RESULT:", data);

      if (data.is_phishing) {
        chrome.action.setBadgeText({
          text: "!",
        });

        chrome.action.setBadgeBackgroundColor({
          color: "#ff0000",
        });
      } else {
        chrome.action.setBadgeText({
          text: "SAFE",
        });

        chrome.action.setBadgeBackgroundColor({
          color: "#00aa00",
        });
      }
    } catch (err) {
      console.error(err);
    }
  }
});
