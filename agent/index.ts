import "./hooks/dyld";
import "./hooks/libSystem";
import "./hooks/objc";
import { backtrace } from "./utils";

Process.setExceptionHandler(function (exp) {
    console.error(`${exp.type} @ ${exp.address}`);
    backtrace(exp.context);
    return false; // TODO: Handle types differently? e.g. breakpoints?
});

console.log("[*] Evading jailbreak detections...");