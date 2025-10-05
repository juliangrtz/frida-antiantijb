# frida-antiantijb

A few simple jailbreak detection bypasses based on Frida. They are far from complete yet.

Proper RASP software will laugh at this.

## Installation

```bash
npm install
```

## Usage

```bash
frida -Uf target -l main.js
```

## Example output

```plain
[*] access("/var/containers/Bundle/Application/OhNo/OhNo.app")
[*] snprintf("/private/var/mobile/Containers/Data/Application/OhNo/tmp/")
[*] symlink("/", "/private/var/mobile/Containers/Data/Application/OhNo/tmp/OhNo")
[*] snprintf("/private/var/mobile/Containers/Data/Application/OhNo/tmp/OhNo/usr/sbin/frida-server")
[!!!] Found suspicious string: /private/var/mobile/Containers/Data/Application/OhNo/tmp/OhNo/usr/sbin/frida-server
0x1039a2cd0 OhNo!0x34dacd0 (0x1034dacd0)
0x1039960b8 OhNo!0x34ce0b8 (0x1034ce0b8)
0x10396d460 OhNo!0x34a5460 (0x1034a5460)
0x10395f268 OhNo!0x3497268 (0x103497268)
0x10396d6d4 OhNo!0x34a56d4 (0x1034a56d4)
0x103a324dc OhNo!0x356a4dc (0x10356a4dc)
0x103a31c60 OhNo!0x3569c60 (0x103569c60)
0x103a35eec OhNo!+[OhNo load]
0x1984007cc libobjc.A.dylib!load_images
0x10506d9d4 dyld!dyld4::RuntimeState::notifyObjCInit(dyld4::Loader const*)
0x105071b54 dyld!dyld4::Loader::runInitializersBottomUp(dyld4::RuntimeState&, dyld3::Array<dyld4::Loader const*>&) const
0x105077840 dyld!dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const
0x10509494c dyld!dyld4::APIs::runAllInitializersForMain()
0x105081c5c dyld!dyld4::prepare(dyld4::APIs&, dyld3::MachOAnalyzer const*)
0x1050804b0 dyld!start
[!!!] Replaced "/private/var/mobile/Containers/Data/Application/OhNo/tmp/OhNo/usr/sbin/frida-server"
```

## TODO

- add more detection strings
- improve dyld detections
