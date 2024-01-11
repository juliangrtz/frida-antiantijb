const module_name = "libsystem_kernel.dylib";
const exp_name = "task_threads";

const strstrModule = Module.getExportByName('libSystem.B.dylib', 'strstr');
const strings = ["tmp", "frida", "gdbus", "gum-js-loop", "gmain",
    "linjector", "substrate", "cydia", "sileo", "bash", "apt", "substitute",
    "pool-spawner", "pool-frida", "com.apple.uikit.eventfetch-th"];

const xxx = Memory.allocUtf8String("xxx");

Interceptor.attach(strstrModule, {
    onEnter: function (args) {
        var str1 = Memory.readCString(args[0])
        var str2 = Memory.readCString(args[1]).toLowerCase();

        for (const str of strings) {
            if (str2.indexOf(str) !== -1) {
                console.log("[*] Frida check -> " + str);
                args[1] = xxx;
                break;
            }
        }
    }
});


function prettyExportDetail(message) {
    return '[*]' + message + '\t' + exp_name + '()\tinside: ' + module_name;
}

if (ObjC.available) {
    try {
        const ptrToExport = Module.findExportByName(module_name, exp_name);
        if (!ptrToExport) {
            throw new Error(prettyExportDetail('Cannot find Export:'));
        }

        Interceptor.attach(ptrToExport, {
            onEnter: function (args) {
                console.log(prettyExportDetail('onEnter() interceptor ->'));
                this._threadCountPointer = new NativePointer(args[2]);
                console.log('[*]Address of Thread Count:' + this._threadCountPointer);
            },

            onLeave: function (retValue) {
                this._patchInt = 4
                console.log(JSON.stringify({
                    return_value: retValue,
                    patched_return_value: this._patchInt,
                    function: exp_name,
                    thread_count: this._threadCountPointer.readPointer().toInt32()
                }));
                retValue.replace(this._patchInt)
            }
        });
    }
    catch (err) {
        console.error(err.message);
    }
}
else {
    console.log("[!]Objective-C Runtime is not available!");
}


Interceptor.attach(strstrModule, {
    onEnter(args) {
        var str = Memory.readUtf8String(args[1]);

        if (str.indexOf("gum-js-loop") != -1) {
            console.log("[+] Bingo: " + str);
            args[1] = bullshit;
        }
    }
});

Interceptor.replace(strcpyModule, new NativeCallback(function (src, dest) {
    var result;

    if (Memory.readUtf8String(dest).indexOf("gum-js-loop") != -1) {
        console.log("[+] Bingo!");
        result = strcpyFunction(src, "gotcha");
    } else {
        result = strcpyFunction(src, dest);
    }

    return result;
}, 'pointer', ['pointer', 'pointer']))



Memory.patchCode(memAddress(fridaCheck), 4, code => {
    let writer = new Arm64Writer(code, { pc: code });
    writer.putRet();
    writer.flush();
    console.log("Patched");
});

Interceptor.attach(memAddress(fridaCheck), {
    onEnter: function (args) {
        console.log("Frida check");
    }
})
