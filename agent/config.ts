export const Config = {
    // Logs more information.
    verbose: true,

    // Whether to perform backtraces when detections are found.
    performBacktrace: false,

    // Whether to initially show all of the loaded images.
    showLoadedImages: false,

    // What to hook.
    hooks: {
        "dyld": true,
        "libSystem": true,
        "antiDebug": true,
        "objc": true,
        "exitFunctions": true,
        "svc": false,
    },

    // Which modules to hook.
    modules: [
        // Add your inclusions here for any modules which are not the main module.
    ] as string[]
}