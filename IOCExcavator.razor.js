// IOC Excavator - collocated JS module. Only the clipboard and handing over a
// file need the browser; everything else happens in C# on the server.
//
// Line comments and plain ASCII throughout: Visual Studio's JavaScript language
// service reports TS1206 / TS1146 on block comments in a .razor.js file.

// Copies text to the clipboard. Returns true when the copy appeared to work.
// The textarea fallback is load-bearing, not legacy politeness: navigator
// .clipboard needs a secure context, and an intranet http:// origin is not one.
export async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // fall through to the manual path below
        }
    }

    const scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);

    try {
        scratch.select();
        return document.execCommand("copy");
    } catch {
        return false;
    } finally {
        scratch.value = "";
        document.body.removeChild(scratch);
    }
}

// Hands the browser a file built on the server. The object URL is revoked
// after the click, so the blob is not left reachable from the page.
export function downloadText(filename, mimeType, content) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
