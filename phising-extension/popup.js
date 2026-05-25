async function getCurrentTab() {
  let queryOptions = {
    active: true,
    currentWindow: true,
  };

  let [tab] = await chrome.tabs.query(queryOptions);

  return tab;
}

async function analyzeWebsite() {
  const tab = await getCurrentTab();

  const url = tab.url;

  document.getElementById("url").innerText = url;

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
      }),
    });

    const data = await response.json();

    console.log(data);

    const status = document.getElementById("status");

    const risk = document.getElementById("risk");

    const confidence = document.getElementById("confidence");

    const details = document.getElementById("details");

    status.innerText = data.prediction;

    // if (data.confidence > 60) {
    //   confidence.innerText = "Confidence: " + data.confidence + "%";
    // } else {
    //   const randomValue = Math.floor(Math.random() * (90 - 60 + 1)) + 60;

    //   confidence.innerText = "Confidence: " + randomValue + "%";
    // }

    risk.innerText = "Risk: " + data.risk_level;

    if (data.is_phishing) {
      status.className = "danger";
    } else {
      status.className = "safe";
    }

    details.innerHTML = `

            <b>Suspicious Features:</b><br>

            ${data.suspicious_features.join("<br>")}

        `;
  } catch (err) {
    console.error(err);

    document.getElementById("status").innerText = "API ERROR";
  }
}

analyzeWebsite();
