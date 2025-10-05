import { isInRightModule } from "../utils";

const libSystemModule = Process.getModuleByName('libSystem.B.dylib');

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
            if (!isInRightModule(this.returnAddress)) {
                this.skip = true;
                return;
            }

            if (f === "dlsym") {
                console.log("[*] dlsym(0x" + args[0].toString(16) + ", \"" + args[1].readUtf8String() + "\")");
            } else if (f === "dlopen" || f === "dlopen_preflight") {
                console.log("[*] " + f + "(\"" + args[0].readUtf8String() + "\")");
            } else if (f === "_dyld_register_func_for_add_image" || f == "_dyld_register_func_for_remove_image") {
                console.log("[*] " + f + "(0x" + args[0].toString(16) + ")");
            } else if (f === "dladdr") {
                console.log("[*] dladdr(0x" + args[0].toString(16) + ") -> " + Process.findModuleByAddress(args[0])?.name);
            } else {
                console.log("[*]", f + "()");
            }
        },

        onLeave(retval) {
            if (this.skip) return;

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
                    retval.replace(Memory.allocUtf8String("*"));
                    break;
                default:
                    return;
            }

            console.log("[!] Returning", retval, "instead of", tmp, "for " + f + ".");
        }
    });
}

export default {};