import { backtrace } from "../utils";

const exitFunctions = [
    { name: "exit", ret: "void", args: ['int'] },
    { name: "_exit", ret: "void", args: ['int'] },
    { name: "abort", ret: "void", args: [] },
    { name: "raise", ret: "int", args: ['int'] },
    //{ name: "pthread_kill", ret: "int", args: ['int'] }
    // TODO signal?
];

const libSystemModule = Process.getModuleByName("libSystem.B.dylib")

exitFunctions.forEach(f => {
    Interceptor.attach(libSystemModule.getExportByName(f.name), {
        onEnter() {
            console.log(`[!!!] ${f.name} call, the app is about to terminate`);
            backtrace(this.context);
        }
    });
});

const libobjCModule = Process.getModuleByName("libobjc.A.dylib");
Interceptor.attach(libobjCModule.getExportByName("exit"), {
    onEnter(_) {
        console.error("[!!!] libobjc EXIT CALLED");
        backtrace(this.context);
    }
});

export default {};