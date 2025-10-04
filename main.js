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
    "/usr/sbin/ssh",
    "/usr/sbin/sshd",
    "/usr/lib/libhooker.dylib",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/var/log/syslog",
    "jailbreak.txt",
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

const idaBase = NULL; // Replace this with the image base in IDA to obtain IDA-friendly addresses.
const memoryBase = Process.mainModule.base;

function memAddress(idaAddr) {
    return ptr(memoryBase).add(ptr(idaAddr).sub(idaBase));
}

function idaAddress(memAddr) {
    return ptr(idaBase).add(ptr(memAddr).sub(memoryBase));
}

function formatAddress(address) {
    return `0x${idaBase == NULL ? address.toString(16) : idaAddress(address).toString(16)}`;
}

function addressToFileOffset(addr) {
    var module = Process.findModuleByAddress(addr);
    if (module) {
        return ptr(addr).sub(module.base);
    } else {
        return ptr(addr);
    }
}

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

// 1 :: File-based checks

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
                    const replacement = Memory.allocUtf8String("*".repeat(primaryStr.length));
                    args[primaryIdx] = replacement;
                    console.log(`[!!!] Redacted "${primaryStr}"`);
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

// 2 :: Portscanning with bind() and connect()

function ntohs(n) {
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF);
}

function getPortFromSockaddr(sockaddrPtr) {
    if (sockaddrPtr === null) {
        return -1;
    }

    try {
        var family = sockaddrPtr.add(1).readU8();
        if (family === 2) { // IPv4
            var portNetOrder = sockaddrPtr.add(2).readU16();
            return ntohs(portNetOrder);
        }

    } catch (e) {
        return -1;
    }

    return -1;
}

const portscanningFunctions = ["bind", "connect"];
const sexyPorts = [22, 44, 1337, 27042];

for (const f of portscanningFunctions) {
    Interceptor.attach(libSystemModule.getExportByName(f), {
        onEnter(args) {
            var sockaddrPtr = args[1];
            this.port = getPortFromSockaddr(sockaddrPtr);
            this.patch = sexyPorts.indexOf(this.port) !== -1;
        },
        onLeave(retval) {
            if (this.patch) {
                console.log(`[!!!] Detected portscanner for port ${this.port} with ${f}. Returning -1...`)
                retval.replace(ptr(-1));
            } else if (verbose) {
                console.log(`[*] Called ${f} with port ${this.port}`);
            }
        }
    });
}

// 3 :: Other checks utilizing libSystem.B.dylib

Interceptor.attach(libSystemModule.getExportByName("fork"), {
    onLeave(retval) {
        console.log(`[!!!] We ain't jailbroken; we're in the sandbox. I swear! --fork()`)
        retval.replace(ptr(-1));

    }
});

Interceptor.attach(libSystemModule.getExportByName("xpc_pipe_routine_with_flags"), {
    onLeave: function (retval) {
        // We completely forbid this. 'tis a shame if a process legitimately uses XPC!
        console.log("[!] xpc_pipe_routine_with_flags()");
        retval.replace(ptr(1));
    }
});

Interceptor.attach(libSystemModule.getExportByName("bootstrap_look_up"), {
    onEnter: function (args) {
        var str = args[1].readCString();
        if (cesspool.includes(str)) {
            console.log(`[!] bootstrap_look_up(${str})`);
            args[1].writeUtf8String("*".repeat(str.length));
        }
    }
});

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
            const tmp = JSON.parse(JSON.stringify(retval));
            switch (f) {
                case "_dyld_get_image_header":
                case "_dyld_get_image_vmaddr_slide":
                case "_dyld_image_count":
                // Warning: Uncommenting this will very likely break the app!
                //case "dlopen":
                case "dlerror":
                    retval.replace(NULL);
                    break;
                case "_dyld_get_image_name":
                    retval.replace(Memory.allocUtf8String("i_like_RASPberries.dylib"));
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


if (ObjC.available) {
    try {
        const nsFileManager = ObjC.classes.NSFileManager;

        Interceptor.attach(nsFileManager["- fileExistsAtPath:"].implementation, {
            onEnter(args) {
                const path = (args[2].isNull() ? "" : ObjC.Object(args[2]).toString());
                console.log(`[!] fileExistsAtPath: ${path}`);
            },
            onLeave(retval) {
                retval.replace(NULL);
            },
        });

        Interceptor.attach(nsFileManager["- isReadableFileAtPath:"].implementation, {
            onEnter(args) {
                const path = (args[2].isNull() ? "" : ObjC.Object(args[2]).toString());
                console.log("[!] isReadableFileAtPath: " + path.toString());
            },
            onLeave(retval) {
                retval.replace(NULL);
            }
        });

        const uiApplication = ObjC.classes.UIApplication;
        Interceptor.attach(uiApplication["- canOpenURL:"].implementation, {
            onEnter(args) {
                this.path = (args[2].isNull() ? "" : ObjC.Object(args[2]).toString());
                console.log(`[!] canOpenURL: ${this.path}`);
            },
            onLeave(retval) {
                retval.replace(NULL);
            },
        });
    } catch (err) {
        console.log("[*] Exception: " + err);
    }
} else {
    console.log("[*] Can't hook Obj-C functions: Runtime not available")
}