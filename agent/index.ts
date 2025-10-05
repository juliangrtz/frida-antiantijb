import { Config } from "./config";

if (Config.hooks["dyld"]) {
    import("./hooks/dyld.ts");
}
if (Config.hooks["libSystem"]) {
    import("./hooks/libSystem.ts");
}
if (Config.hooks["objc"]) {
    import("./hooks/objc.ts");
}
if (Config.hooks["svc"]) {
    import("./hooks/svcs.ts");
}

import { backtrace } from "./utils";

Process.setExceptionHandler(function (exp) {
    console.error(`${exp.type} @ ${exp.address}`);
    backtrace(exp.context);
    return false; // TODO: Handle types differently? e.g. breakpoints?
});

console.log("[*] Evading jailbreak detections...");