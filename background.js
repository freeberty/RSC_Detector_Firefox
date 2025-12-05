// background.js - Firefox version
// Handles badge updates and header modification (replaces declarativeNetRequest)

// Badge update handler
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "update_badge" && sender.tab) {
        browser.browserAction.setBadgeBackgroundColor({
            tabId: sender.tab.id,
            color: "#FF0000"
        });
        browser.browserAction.setBadgeText({
            tabId: sender.tab.id,
            text: "!"
        });
    }
});

// Header modification using webRequest API (replaces rules.json)
browser.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        let headers = details.requestHeaders;

        // Remove Origin header
        headers = headers.filter(h => h.name.toLowerCase() !== 'origin');

        // Set/modify Referer header
        let refererFound = false;
        for (let header of headers) {
            if (header.name.toLowerCase() === 'referer') {
                header.value = 'Referer-modified-value';
                refererFound = true;
                break;
            }
        }
        if (!refererFound) {
            headers.push({ name: 'Referer', value: 'Referer-modified-value' });
        }

        return { requestHeaders: headers };
    },
    { urls: ["<all_urls>"], types: ["xmlhttprequest"] },
    ["blocking", "requestHeaders"]
);
