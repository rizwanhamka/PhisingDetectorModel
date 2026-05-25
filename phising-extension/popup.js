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
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    const status = document.getElementById("status");
    const risk = document.getElementById("risk");
    const confidence = document.getElementById("confidence");
    const details = document.getElementById("details");

    status.innerText = data.prediction;
    risk.innerText = data.risk_level;
    // confidence.innerText = `${data.confidence ?? "-"}%`;

    // style status
    status.className = data.is_phishing ? "danger" : "safe";

    // risk styling ringan
    risk.className =
      data.risk_level === "HIGH"
        ? "danger"
        : data.risk_level === "MEDIUM"
          ? "warning"
          : "safe";

    // details
    details.innerHTML = data.suspicious_features?.length
      ? data.suspicious_features.join("<br>")
      : "No suspicious features detected";
  } catch (err) {
    console.error(err);
    document.getElementById("status").innerText = "API ERROR";
    document.getElementById("status").className = "danger";
  }
}

analyzeWebsite();
