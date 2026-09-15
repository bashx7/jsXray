function renderUserData(rawHtml, scriptCode, redirectUrl) {
  document.getElementById("profile").innerHTML = rawHtml;
  document.write("<p>" + rawHtml + "</p>");
  eval(scriptCode);
  window.location.href = redirectUrl;
  window.postMessage({ type: "SYNC", payload: rawHtml }, "*");
}
