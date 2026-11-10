// IOC Excavator - collocated JS module.
//
// Loaded by IOCExcavator.razor in OnAfterRenderAsync from
// ./Components/Pages/IOCExcavator/IOCExcavator.razor.js
//
// Deliberately tiny. Only two things genuinely need the browser: the
// clipboard, and handing a generated file to the user. All parsing, scoring
// and Splunk building happens in C# on the server, so a crafted advisory
// never becomes JavaScript data.
//
// Line comments and plain ASCII throughout: Visual Studio's JavaScript
// language service reports TS1206 / TS1146 on block comments in a .razor.js
// file, and those warnings are pure noise in the Error List.

// Copies text to the clipboard. Returns true when the copy appeared to work.
//
// navigator.clipboard needs a secure context. Plain http://localhost counts as
// one, but an intranet http:// origin does not, so the textarea fallback is
// load-bearing rather than legacy-browser politeness.
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
        // clear the element's own copy before it leaves the DOM
        scratch.value = "";
        document.body.removeChild(scratch);
    }
}

// Hands the browser a file built on the server.
//
// The object URL is revoked right after the click, so the blob is not left
// reachable from the page.
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
