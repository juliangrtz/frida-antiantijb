const cesspool = [
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/apt",
    "/etc/profile.d/terminal.sh",
    "/etc/ssh/sshd_config",
    "/pguntether",
    "/private/etc/profile.d/terminal.sh",
    "/private/var/lib/apt",
    "/private/var/stash",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/lib/libhooker.dylib",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/var/log/syslog",
    "blackra1n",
    "comle.uikit.eventfetch-th",
    "cydia",
    "evasi0n",
    "fakecarrier",
    "frida",
    "gdbus",
    "gmain",
    "gum-js-loop",
    "intelliscreen",
    "launchdaemons",
    "linjector",
    "mxtube",
    "pool-spawner",
    "sbsettings",
    "sileo",
    "substitute",
    "substrate",
    "terminal",
    "trollstore",
    "winterboard",
    // 🙃
    "bi.txt",
    "ii.txt",
    "config-encrypt.txt",
    "jigsaw.txt"
];

const verbose = false;
const performBacktrace = true;

Process.setExceptionHandler(function (exp) {
    console.log(`${exp.type} @ ${exp.address}`);
    backtrace(exp.context);
    return false;
});

/* 
----------------
HELPER FUNCTIONS
----------------
*/

function isEvilString(candidate) {
    for (const evil of cesspool) {
        if (candidate.toLowerCase().indexOf(evil) !== -1) {
            console.log("[!!!] Found suspicious string: " + candidate);
            return true;
        }
    }

    return false;
}

function safeReadUtf8String(ptr) {
    try {
        if (ptr === null) return null;
        return ptr.readUtf8String();
    } catch (e) {
        console.warn("[*] Failed to read UTF8 string @ " + ptr.toString(16));
        return null;
    }
}

function safeWriteUtf8String(ptr, value) {
    try {
        if (ptr === 0) return false;
        ptr.writeUtf8String(value);
        return true;
    } catch (e) {
        console.warn("[*] Failed to write UTF8 string @ " + ptr.toString(16));
        return false;
    }
}

function backtrace(ctx) {
    const backtrace = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);

    backtrace.forEach(b => {
        if (b.moduleName === Process.mainModule.name || verbose) {
            console.log(b);
        }
    });
}

/* 
-------------------
LIBSYSTEM FUNCTIONS
-------------------
*/

const libSystemModule = Process.getModuleByName('libSystem.B.dylib');

// name -> [stringArgIndices, isOnEnter]
// Store only the index of the buffer's pointer for functions which store the result in a buffer, e.g. snprintf
const libsystemStringFunctions = {
    "access": [[0], true],
    "open": [[0], true],
    "fopen": [[0], true],
    "freopen": [[0], true],
    "strcmp": [[0, 1], true],
    "strstr": [[0, 1], true],
    "symlink": [[0, 1], true],
    "stat": [[0], true],
    "stat64": [[0], true],
    "lstat": [[0], true],
    "lstat64": [[0], true],
    "snprintf": [[0], false],
    "vprintf": [[0], false],
    "vsnprintf": [[0], false],
}

for (const [name, params] of Object.entries(libsystemStringFunctions)) {
    const indices = params[0];
    const onEnter = !!params[1];

    let target;
    try {
        target = libSystemModule.getExportByName(name);
    } catch (err) {
        console.warn(`[*] Export ${name} was not found: ${err.message}`);
        continue;
    }

    Interceptor.attach(target, {
        onEnter(args) {
            const primaryIdx = indices[0];

            if (!onEnter) {
                try {
                    this._savedArgPtr = args[primaryIdx];
                } catch (e) {
                    this._savedArgPtr = null;
                }
                return;
            }

            const readStrings = [];
            for (let idx of indices) {
                const s = safeReadUtf8String(args[idx]);
                readStrings.push(s === null ? "<null>" : s);
            }

            if (verbose) {
                console.log(`[*] ${name}(${readStrings.map(s => `"${s}"`).join(", ")})`);
            }

            const primaryStr = readStrings[0];
            if (primaryStr === null || primaryStr === "<null>") return;

            if (isEvilString(primaryStr)) {
                if (performBacktrace) backtrace(this.context);

                try {
                    const replacement = Memory.allocUtf8String(".");
                    args[primaryIdx] = replacement;
                    console.log(`[!!!] Replaced "${primaryStr}" -> "."`);
                } catch (e) {
                    if (safeWriteUtf8String(args[primaryIdx], ".")) {
                        console.log(`[!!!] Overwrote buffer of "${primaryStr}" -> "."`);
                    } else {
                        console.warn(`[*] Failed to replace "${primaryStr}": ${e.message}`);
                    }
                }
            }
        },

        onLeave(_) {
            if (onEnter) return;

            const savedPtr = this._savedArgPtr;
            if (!savedPtr) return;

            const str = safeReadUtf8String(savedPtr);
            if (str === null) return;

            if (verbose) {
                console.log(`[*] ${name}("${str}")`);
            }

            if (isEvilString(str)) {
                if (performBacktrace) backtrace(this.context);

                if (safeWriteUtf8String(savedPtr, ".")) {
                    console.log(`[!!!] Replaced "${str}" in-place`);
                } else {
                    console.warn(`[*] Failed to replace "${str}" in-place`);
                }
            }
        }
    });
}

/* 
----
DYLD
----
*/

const dyldFunctions = [
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html
    "_dyld_get_image_header",
    "_dyld_get_image_name",
    "_dyld_get_image_vmaddr_slide",
    "_dyld_image_count",
    "_dyld_register_func_for_add_image",
    "_dyld_register_func_for_remove_image",
    "dladdr",
    "dlclose",
    "dlerror",
    "dlopen",
    "dlopen_preflight",
    "dlsym"
];

for (const f of dyldFunctions) {
    Interceptor.attach(libSystemModule.getExportByName(f), {
        onEnter(args) {
            if (f === "dlsym") {
                console.log("[*] dlsym(0x" + args[0].toString(16) + ", \"" + args[1].readUtf8String() + "\")");
            } else if (f === "dlopen" || f === "dlopen_preflight") {
                console.log("[*] " + f + "(\"" + args[0].readUtf8String() + "\")");
            } else if (f === "_dyld_register_func_for_add_image" || f == "_dyld_register_func_for_remove_image") {
                console.log("[*] " + f + "(0x" + args[0].toString(16) + ")");
            } else if (f === "dladdr") {
                console.log("[*] dladdr(0x" + args[0].toString(16) + ")");
            } else {
                console.log("[*]", f + "()");
            }
        },

        onLeave(retval) {
            const tmp = retval;
            switch (f) {
                case "_dyld_get_image_header":
                case "_dyld_get_image_vmaddr_slide":
                case "_dyld_image_count":
                case "dlopen":
                case "dlerror":
                    retval = NULL;
                    break;
                case "_dyld_get_image_name":
                    retval = Memory.allocUtf8String(".");
                    break;
                default:
                    return;
            }

            console.log("[*] Returning", retval, "instead of", tmp, "for " + f + ".");
        }
    });
}

/* 
---------------------
OBJECTIVE C FUNCTIONS
---------------------
*/

// Taken from https://gist.github.com/izadgot/5783334b11563fb08fee4cd250455ede
// Might have to be revised.

if (ObjC.available) {
    try {
        const nsFileManager = ObjC.classes.NSFileManager;
        const uiApplication = ObjC.classes.UIApplication;

        Interceptor.attach(nsFileManager["- fileExistsAtPath:"].implementation, {
            onEnter(args) {
                this.is_common_path = false;
                try {
                    this.path = (args[2].isNull() ? "" : ObjC.Object(args[2]).toString());
                } catch (e) {
                    this.path = "<invalid>";
                }

                if (cesspool.indexOf(this.path) !== -1) {
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                if (!this.is_common_path) return;

                if (retval.isNull()) {
                    console.log(`[*] fileExistsAtPath: try to check for ${this.path} failed`);
                    return;
                }

                console.log(
                    `[*] fileExistsAtPath: check for ${this.path} was successful with: ${retval.toString()}, marking it as failed.`
                );
                retval.replace(ptr("0x0"));
            },
        });

        Interceptor.attach(uiApplication["- canOpenURL:"].implementation, {
            onEnter(args) {
                this.is_flagged = false;
                try {
                    this.path = (args[2].isNull() ? "" : ObjC.Object(args[2]).toString());
                } catch (e) {
                    this.path = "<invalid>";
                }

                const app = this.path.split(":")[0].toLowerCase();
                if (cesspool.indexOf(app) !== -1) {
                    this.is_flagged = true;
                }
            },
            onLeave(retval) {
                if (!this.is_flagged) return;
                if (retval.isNull()) return;

                console.log(
                    `[*] canOpenURL: check for ${this.path} was successful with: ${retval.toString()}, marking it as failed.`
                );
                retval.replace(ptr("0x0"));
            },
        });
    } catch (err) {
        console.log("[*] Exception: " + err);
    }
} else {
    console.log("[*] Objective-C Runtime is not available!");
}