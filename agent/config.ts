export const Config = {
    // Logs more information.
    verbose: true,

    // Whether to perform backtraces when detections are found.
    performBacktrace: false,

    // What to hook.
    hooks: {
        "dyld": true,
        "libSystem": true,
        "objc": true,
        "svc": false,
        "exitFunctions": true,
    },

    // Which modules to hook.
    modules: [
        // Add your inclusions here for any modules which are not the main module.
    ] as string[]
}