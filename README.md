# pairipcore vm

Further research based on
[pairipcore](https://github.com/Solaree/pairipcore), focusing on the virtual
machine (VM) used to virtualize code in Android apps as a protection mechanism (**P**l**A**y**I**nteg**RI**ty**P**rotect - pairip).

> [!IMPORTANT]
> Google designed the VM to be custom for every release of an application. The
> analysis provided here acan be used up to the point where opcodes are analyzed.
> A workaround is WIP!

> [!NOTE]
> A detailed writeup is work-in-progress and will be published to GitHub Pages
> soon. Decompiler and Disassembler are WIP!

## Update (01/20/2025) - *will be moved to documentation soon*


Rust package to scan for string XOR key. Installation w/ cargo:

```bash
cargo install --git https://github.com/MatrixEditor/pairipcore-vm
```

Usage: extract XOR key

```bash
$ pairip find-key ./assets/data.vmcode
[filepath]: ./assets/data.vmcode
[formatids]: (30)
[key]:
 - offset: 0x1752f
 - material: ab162bc02f4437b67f51318f394013112aec38dd37da4f225f5497001d3ba65460adbf508c86fe67c9c2afaf5fba71c19a361b712eb643330aa5e5eaf92059f174111325f287d8b68ecda823b36fd84e52e8bed9c1a06ac2285677d943fc926b0c23f8a968b8f7d424acad2d8857928ab379cd5965d9aba8d19387916ff563eba005c7d4c63f80b9f5a3d07c7f4f0a27e1f5be98b5d1d9505f6c491878a216f8f7ab03f0af5fe8f8f6cecc0dd2b3b4664ff2a93cd70e0405a485b526cfbc16d3fe0bb8fab1fb34f816769296e3ee97f1c1ad15e30f183a5e2ffe141add1be97111c8c3aaf2a0ca227d91cdc8015f3848e96abef41a42cc6da2295c1d66b638
```

To list all strings within a file, use `strings`:

```bash
$ pairip strings ./data.vmcode
 WARNING: key not specified, trying to resolve dynamically...
0x0000b6: yWUKCt
0x00011a: lib/x86/libmapbufferjni.so
0x000152: anwhcacYyM
0x0001e6: UbEvkSwTN
0x0001f1: lib/x86_64/libreactnativejni.so
0x00032c: PASTE
0x000366: BxCUTpJ
0x0003a5: CheckCreateCustomVoiceSegmentProgressResponse(status=
0x00047f: iOQyjctRdfxcvc
```

## Disclaimer

The information presented here is for educational purposes only!

## Overview

Moved to GitHub-Pages [https://matrixeditor.github.io/pairipcore-vm/](https://matrixeditor.github.io/pairipcore-vm/).
