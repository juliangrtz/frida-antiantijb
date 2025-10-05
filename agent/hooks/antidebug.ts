import { LIBSYSTEM_MODULE } from "../modules";

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("ptrace"), {
    onEnter: function (args) {
        console.log("[!!!] ptrace");
        var request = args[0].toInt32();
        if (request == 31) { // PT_DENY_ATTACH
            args[0] = ptr(-1);
        }
    }
});

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("getppid"), {
    onLeave: function (retval) {
        console.log("[!!!] getppid");
        var ret = retval.toInt32();
        if (ret !== 1) {
            retval.replace(ptr(0x1));
        }
    }
});

Interceptor.attach(LIBSYSTEM_MODULE.getExportByName("sysctl"), {
    onEnter: function (_) {
        this.kinfo = (this.context as Arm64CpuContext).x2;
    },
    onLeave: function (_) {
        console.log("[!!!] sysctl");
        var p = this.kinfo.add(32);
        var p_flag = p.readInt() & 0x00000800;
        if (p_flag === 0x800) {
            p.writeInt(0);
        }
    }
});