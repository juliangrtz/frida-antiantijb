// One could also use Frida's Stalker API here but I don't think it's efficient to trace every single instruction.

const MAX_HOOKS = 512;
const IGNORE_MODULES = ["dyld", "libsystem_kernel"];

let attachedCount = 0;
const attachedAddrs = new Set<string>();

function moduleIgnored(name?: string, path?: string): boolean {
    const check = ((name || path || "")).toLowerCase();
    for (const p of IGNORE_MODULES) {
        if (check.indexOf(p.toLowerCase()) >= 0) return true;
    }
    return false;
}

function scanModuleForSvc(targetModule: Module) {
    if (moduleIgnored(targetModule.name, targetModule.path)) return;
    const ranges = targetModule.enumerateRanges('r-x');
    for (const r of ranges) {
        try {
            Memory.scan(r.base, r.size, "01 10 00 D4", { // TODO Handle ?? ?? ?? D4, Yes I'm looking at you, Arxan
                onMatch: function (address, _) {
                    if (attachedCount >= MAX_HOOKS) return;
                    try {
                        const insn = Instruction.parse(address);
                        if (!insn || !insn.mnemonic) return;
                        if (insn.mnemonic.toLowerCase() !== "svc") return;

                        const addrStr = address.toString();
                        if (attachedAddrs.has(addrStr)) return;

                        Interceptor.attach(address, {
                            onEnter(_) {
                                try {
                                    let num;
                                    try {
                                        num = (this.context as Arm64CpuContext).x16.toInt32();
                                    } catch {
                                        num = 0;
                                    }

                                    console.error(`${address.toString()} ${Process.getCurrentThreadId()} ${num}\n`);

                                    if (num in [2, 5, 26, 33]) { // fork, open, ptrace, access
                                        (this.context as Arm64CpuContext).x0 = ptr(-1);
                                    }
                                } catch {
                                }
                            }
                        });

                        attachedAddrs.add(addrStr);
                        attachedCount++;
                    } catch {
                    }
                },
                onError: function (_) { },
                onComplete: function () { }
            });
        } catch {
        }
    }
}

scanModuleForSvc(Process.mainModule);

// Alternatively scan ALL modules
/* 
const RESCAN_INTERVAL_MS = 500;

function scanAllModules() {
    try {
        const mods = Process.enumerateModules();
        for (const m of mods) {
            if (attachedCount >= MAX_HOOKS) break;
            scanModuleForSvc(m);
        }
    } catch { }
}

scanAllModules();

let rescanTimer: any = setInterval(() => {
    if (attachedCount >= MAX_HOOKS) {
        clearInterval(rescanTimer);
        rescanTimer = null;
        return;
    }
    scanAllModules();
}, RESCAN_INTERVAL_MS);
*/

export default {};