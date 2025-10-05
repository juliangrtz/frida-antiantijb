import { LIBOBJC_MODULE, LIBSYSTEM_MODULE } from "../modules";
import { backtrace } from "../utils";

const exitFunctions = [
    { name: "exit", ret: "void", args: ['int'] },
    { name: "_exit", ret: "void", args: ['int'] },
    { name: "abort", ret: "void", args: [] },
    { name: "raise", ret: "int", args: ['int'] },
    //{ name: "pthread_kill", ret: "int", args: ['int'] }
    // TODO signal?
];

exitFunctions.forEach(f => {
    Interceptor.attach(LIBSYSTEM_MODULE.getExportByName(f.name), {
        onEnter() {
            console.log(`[!!!] ${f.name} call, the app is about to terminate`);
            backtrace(this.context);
        }
    });
});

Interceptor.attach(LIBOBJC_MODULE.getExportByName("exit"), {
    onEnter(_) {
        console.error("[!!!] libobjc EXIT CALLED");
        backtrace(this.context);
    }
});

export default {};