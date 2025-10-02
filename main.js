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
    "backgrounder",
    "bitesms",
    "blackra1n",
    "comle.uikit.eventfetch-th",
    "cydia",
    "evasi0n",
    "fakecarrier",
    "frida",
    "gdbus",
    "gmain",
    "gum-js-loop",
    "icy",
    "ifile",
    "intelliscreen",
    "iprotect",
    "launchdaemons",
    "linjector",
    "mxtube",
    "pirni",
    "pool-spawner",
    "rockapp",
    "sbsettings",
    "sbsetttings",
    "sileo",
    "substitute",
    "substrate",
    "terminal",
    "trollstore",
    "winterboard",
];

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

/* 
-------------------
LIBSYSTEM FUNCTIONS
-------------------
*/

const libSystemModule = Process.getModuleByName('libSystem.B.dylib');

// name -> [stringArgIdx, isOnEnter]
const libsystemStringFunctions = {
    "access": [0, true],
    "open": [0, true],
    "fopen": [0, true],
    "freopen": [0, true],
    "snprintf": [0, false],
    "vprintf": [0, false],
    "vsnprintf": [0, false],
    "stat": [0, false],
    "stat64": [0, false],
    "lstat": [0, false],
    "lstat64": [0, false],
    "strcmp": [0, true],
    "strstr": [0, true],
    "symlink": [0, true]
}

let tmp = ptr(0);
for (const [name, params] of Object.entries(libsystemStringFunctions)) {
    Interceptor.attach(libSystemModule.getExportByName(name), {
        onEnter(args) {
            var idx = params[0];

            if (!params[1]) {
                tmp = args[idx];
                return;
            }

            var str = args[idx].readUtf8String();

            if (str == null) {
                return;
            }

            if (["strstr", "strcmp", "symlink"].indexOf(name) !== -1) {
                var str2 = args[idx + 1].readUtf8String();
                console.log("[*] " + name + "(\"" + str + "\"" + ", \"" + str2 + "\")");
            } else {
                console.log("[*] " + name + "(\"" + str + "\")");
            }

            if (isEvilString(str)) {
                var strReplacement = Memory.allocUtf8String(".");
                args[idx] = strReplacement;
                console.log("[!!!] Replaced \"" + str + "\"");
            }
        },

        onLeave(_) {
            if (params[1] || tmp == ptr(0)) {
                return;
            }

            var str = tmp.readUtf8String();

            if (str == null) {
                return;
            }

            console.log("[*] " + name + "(\"" + str + "\")");

            if (isEvilString(str)) {
                tmp.writeUtf8String(".");
                console.log("[!!!] Replaced \"" + str + "\"");
            }
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