// WIP.

const libSystemModule = Process.getModuleByName('libSystem.B.dylib');
const functions = [
  // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html
  "_dyld_get_image_header",
  "_dyld_get_image_name",
  "_dyld_get_image_vmaddr_slide",
  "_dyld_image_count",
  "_dyld_register_func_for_add_image",
  "_dyld_register_func_for_remove_image",
  /*
  "dladdr",
  "dlclose",
  "dlerror",
  "dlinfo",
  "dlopen",
  "dlopen_preflight",
  */
  // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html
  "dlsym",
];
const patch = false;
const newImageCount = 0; // Will defeat simple loop-based detections.
const strReplacement = Memory.allocUtf8String("."); // Will defeat simple string-based detections.

for (const f of functions) {
  Interceptor.attach(libSystemModule.getExportByName(f), {
    onEnter(args) {
      if (f == "dlsym") {
        console.log("[*] dlsym(0x" + args[0].toString(16) + ", \"" + args[1].readUtf8String() + "\")");
      } else {
        console.log("[*]", f + "()");
      }
    },

    onLeave(retval) {
      if (patch) {
        var tmp = retval;
        switch (f) {
          case "_dyld_get_image_header":
            retval = ptr(0);
            break;
          case "_dyld_get_image_vmaddr_slide":
            retval = ptr(0);
            break;
          case "_dyld_get_image_name":
            retval = strReplacement;
            break;
          case "_dyld_image_count":
            retval = newImageCount;
            break;
          default:
            // TODO: Add others.
            // dlsym must handle specific libraries and functions.
            break;
        }
        console.log("[*] Returning", retval, "instead of", tmp, ".");
      }
    }
  });
}
