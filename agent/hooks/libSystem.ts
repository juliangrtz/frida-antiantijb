import { backtrace, safeReadUtf8String, safeWriteUtf8String, isEvilString, isInRightModule } from "../utils";
import { Config } from "../config";
import { LIBSYSTEM_MODULE } from "../modules";

// 1 :: File-based checks

type StringFunctionConfig = {
    [name: string]: [indices: number[], isOnEnter: boolean];
};

const libsystemStringFunctions: StringFunctionConfig = {
    access: [[0], true],
    open: [[0], true],
    fopen: [[0], true],
    freopen: [[0], true],
    strcmp: [[0, 1], true],
    strstr: [[0, 1], true],
    symlink: [[0, 1], true],
    stat: [[0], true],
    stat64: [[0], true],
    lstat: [[0], true],
    lstat64: [[0], true],
    snprintf: [[0], false],
    vprintf: [[0], false],
    vsnprintf: [[0], false],
};

for (const [name, [indices, onEnter]] of Object.entries(libsystemStringFunctions)) {
    Interceptor.attach(LIBSYSTEM_MODULE.getExportByName(name), {
        onEnter(args) {
            if (!isInRightModule(this.returnAddress)) {
                this.skip = true;
                return;
            }

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

            if (Config.verbose) {
                console.log(`[*] ${name}(${readStrings.map(s => `"${s}"`).join(", ")})`);
            }

            const primaryStr = readStrings[0];
            if (primaryStr === null || primaryStr === "<null>") return;

            if (isEvilString(primaryStr) || name === "access") {
                if (Config.performBacktrace) backtrace(this.context);

                try {
                    const replacement = Memory.allocUtf8String("*".repeat(primaryStr.length));
                    args[primaryIdx] = replacement;
                    console.log(`[!!!] Redacted "${primaryStr}"`);
                } catch (e) {
                    if (safeWriteUtf8String(args[primaryIdx], ".")) {
                        console.log(`[!!!] Overwrote buffer of "${primaryStr}" -> "."`);
                    } else {
                        console.warn(`[*] Failed to replace "${primaryStr}"`);
                    }
                }
            }
        },

        onLeave(_) {
            if (this.skip || onEnter) return;

            const savedPtr = this._savedArgPtr;
            if (!savedPtr) return;

            const str = safeReadUtf8String(savedPtr);
            if (str === null) return;

            if (Config.verbose) {
                console.log(`[*] ${name}("${str}")`);
            }

            if (isEvilString(str)) {
                if (Config.performBacktrace) backtrace(this.context);

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

function ntohs(n: number) {
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF);
}

function getPortFromSockaddr(sockaddrPtr: NativePointer) {
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
    Interceptor.attach(LIBSYSTEM_MODULE.getExportByName(f), {
        onEnter(args) {
            var sockaddrPtr = args[1];
            this.port = getPortFromSockaddr(sockaddrPtr);
            this.patch = sexyPorts.indexOf(this.port) !== -1;
        },
        onLeave(retval) {
            if (this.patch) {
                console.log(`[!!!] Detected portscanner for port ${this.port} with ${f}. Returning -1...`)
                retval.replace(ptr(-1));
            } else if (Config.verbose) {
                console.log(`[*] Called ${f} with port ${this.port}`);
            }
        }
    });
}

// 3 :: Other checks utilizing libSystem.B.dylib

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("fork"), {
    onLeave(retval) {
        console.log(`[!!!] We ain't jailbroken; we're in the sandbox. I swear! --fork()`)
        retval.replace(ptr(-1));
    }
});

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("xpc_pipe_routine_with_flags"), {
    onLeave: function (retval) {
        // We completely forbid this. 'tis a shame if a process legitimately uses XPC!
        console.log("[!] xpc_pipe_routine_with_flags()");
        retval.replace(ptr(1));
    }
});

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("bootstrap_look_up"), {
    onEnter: function (args) {
        var str = args[1].readCString();
        if (str && isEvilString(str)) {
            console.log(`[!] bootstrap_look_up(${str})`);
            args[1].writeUtf8String("*".repeat(str.length));
        }
    }
});

export default {};