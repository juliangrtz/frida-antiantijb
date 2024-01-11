Process
  .getModuleByName("libSystem.B.dylib")
  .enumerateExports().filter(ex => ex.type === 'function' && ['dlsym'].includes(ex.name))
  .forEach(ex => {
    Interceptor.attach(ex.address, {
      onEnter: function (args) {
        var a2 = Memory.readUtf8String(args[1]);
        console.log(a2);
      }
    })
  })