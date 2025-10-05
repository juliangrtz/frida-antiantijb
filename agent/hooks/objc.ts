import { isEvilString } from "../utils";
import ObjC from "frida-objc-bridge";

// TODO: Find out what low-level functions the ObjC wrappers call.
// This will allow getting rid of the frida-objc-bridge dependency.

if (ObjC.available) {
    try {
        function getCallbacks(f: string) {
            let x: InvocationListenerCallbacks = {
                onEnter(args: InvocationArguments) {
                    this.path = (args[2].isNull() ? "" : new ObjC.Object(args[2]).toString());
                    this.patch = isEvilString(this.path);
                },
                onLeave(retval: InvocationReturnValue) {
                    if (this.patch) {
                        console.log(`[!!!] ${f}: ${this.path}`);
                        retval.replace(NULL);
                    }
                }
            }
            return x;
        };

        const nsFileManager = ObjC.classes.NSFileManager;
        const nsFileManagerFunctions = [
            "fileExistsAtPath", "isReadableFileAtPath", "isExecutableFileAtPath",
        ];

        for (const f of nsFileManagerFunctions) {
            try {
                Interceptor.attach(nsFileManager[`- ${f}:`].implementation, getCallbacks(f));
            } catch {
                console.error(f);
            }
        }

        const uiApplication = ObjC.classes.UIApplication;
        Interceptor.attach(uiApplication[`- canOpenURL:`].implementation, getCallbacks("canOpenURL"));

        const nsDictionary = ObjC.classes.NSDictionary;
        Interceptor.attach(nsDictionary[`+ dictionaryWithContentsOfFile:`].implementation, getCallbacks("dictionaryWithContentsOfFile"));

        const nsString = ObjC.classes.NSString;
        Interceptor.attach(nsString["- writeToFile:atomically:encoding:error:"].implementation, getCallbacks("writeToFile"));

        const nsData = ObjC.classes.NSData;
        Interceptor.attach(nsData["+ dataWithContentsOfFile:options:error:"].implementation, getCallbacks("dataWithContentsOfFile:options:error"));
        Interceptor.attach(nsData["+ dataWithContentsOfFile:"].implementation, getCallbacks("dataWithContentsOfFile"));
    } catch (err) {
        console.log("[*] Exception: " + err);
    }
} else {
    console.log("[*] Can't hook Obj-C functions: Runtime not available")
}

export default {};