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
    }
}