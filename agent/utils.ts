import { CESSPOOL } from "./cesspool";
import { Config } from "./config";

type address = string | number

// Replace this with the image base in IDA to obtain IDA-friendly addresses.
const idaBase = NULL;

export const MAIN_MODULE_NAME = Process.mainModule.name;
export const MEMORY_BASE = Process.mainModule.base;

export function memAddress(idaAddr: address) {
    return MEMORY_BASE.add(ptr(idaAddr).sub(idaBase));
}

export function idaAddress(memAddr: address) {
    return idaBase.add(ptr(memAddr).sub(MEMORY_BASE));
}

export function formatAddress(address: address) {
    return `0x${idaBase == NULL ? address.toString(16) : idaAddress(address).toString(16)}`;
}

export function addressToFileOffset(address: NativePointer) {
    var module = Process.findModuleByAddress(address);
    if (module) {
        return address.sub(module.base);
    } else {
        return address;
    }
}

export function isEvilString(candidate: string) {
    for (const evil of CESSPOOL) {
        if (candidate.toLowerCase().indexOf(evil) !== -1) {
            console.log("[!!!] Found suspicious string: " + candidate);
            return true;
        }
    }

    return false;
}

export function safeReadUtf8String(ptr: NativePointer) {
    try {
        if (ptr === null) return null;
        return ptr.readUtf8String();
    } catch (e) {
        console.warn("[*] Failed to read UTF8 string @ " + ptr.toString(16));
        return null;
    }
}

export function safeWriteUtf8String(ptr: NativePointer, value: string) {
    try {
        if (ptr.isNull()) return false;
        ptr.writeUtf8String(value);
        return true;
    } catch (e) {
        console.warn("[*] Failed to write UTF8 string @ " + ptr.toString(16));
        return false;
    }
}

export function backtrace(ctx: CpuContext) {
    const backtrace = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);

    backtrace.forEach(b => {
        if (b.moduleName === Process.mainModule.name || Config.verbose) {
            console.log(b);
        }
    });
}

export function stalkCalls() {
    Process.enumerateThreads().forEach(function (thread) {
        Stalker.follow(thread.id, {
            events: {
                call: true,
                ret: false,
                exec: false,
                block: false,
                compile: false
            },
            onCallSummary: function (summary) {
                for (var target in summary) {
                    console.log("Thread " + thread.id + " Call to: " + `${idaAddress(target)}` + " (" + summary[target] + " times)");
                }
            }
        });
    });
}