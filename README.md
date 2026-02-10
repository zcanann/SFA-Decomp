Star Fox Adventures Decompilation
[![Build Status]][actions] [![Progress]][progress site] [![DOL Progress]][progress site]
===============================
[Build Status]: https://github.com/zcanann/SFA-Decomp/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/zcanann/SFA-Decomp/actions/workflows/build.yml
[Progress]: https://decomp.dev/zcanann/SFA-Decomp.svg?mode=shield&measure=code&label=Code&category=all
[DOL Progress]: https://decomp.dev/zcanann/SFA-Decomp.svg?mode=shield&measure=code&label=DOL&category=dol
[progress site]: https://decomp.dev/zcanann/SFA-Decomp
This is the decompilation for Star Fox Adventures for the Nintendo GameCube.

There are 3 versions of this game: JP, EN, and PAL (EU), with the EN having an initial v1.00 release, and a patched version v1.01.

**⚠️ Assets are not bundled with this repository. You must obtain these on your own. ⚠️**

# Contribution Guide

## Beginners Contribution Guide
The most direct way to contribute that requires minimal setup, is to simply pick a 10-99% matching section from [the decomp tracker](https://decomp.dev/zcanann/SFA-Decomp), and update the code until it has a higher match score.

Refer to the sections on building and diffing. Once you have this set up, all you need to do is modify .cpp and .h files until the score goes up!

## Advanced Contribution Guide
Splits and symbols are largely incomplete at this point. Until these are in a better place, contributing code is quite difficult.

# Dependencies

## Windows

On Windows, it's **highly recommended** to use native tooling. WSL or msys2 are **not** required.  
When running under WSL, [objdiff](#diffing) is unable to get filesystem notifications for automatic rebuilds.

- Install [Python](https://www.python.org/downloads/) and add it to `%PATH%`.
  - Also available from the [Windows Store](https://apps.microsoft.com/store/detail/python-311/9NRWMJP3717K).
- Download [ninja](https://github.com/ninja-build/ninja/releases) and add it to `%PATH%`.
  - Quick install via pip: `pip install ninja`

## macOS

- Install [ninja](https://github.com/ninja-build/ninja/wiki/Pre-built-Ninja-packages):

  ```sh
  brew install ninja
  ```

[wibo](https://github.com/decompals/wibo), a minimal 32-bit Windows binary wrapper, will be automatically downloaded and used.

## Linux

- Install [ninja](https://github.com/ninja-build/ninja/wiki/Pre-built-Ninja-packages).

[wibo](https://github.com/decompals/wibo), a minimal 32-bit Windows binary wrapper, will be automatically downloaded and used.

## Building

- Clone the repository:

  ```sh
  git clone https://github.com/my/repo.git
  ```

- Copy your game's disc image to `orig/GAMEID`.
  - Supported formats: ISO (GCM), RVZ, WIA, WBFS, CISO, NFS, GCZ, TGC
  - After the initial build, the disc image can be deleted to save space.

- Configure:

  ```sh
  python configure.py
  ```

  To use a version other than `GAMEID` (USA), specify it with `--version`.

- Build:

  ```sh
  ninja
  ```

## Diffing

Once the initial build succeeds, an `objdiff.json` should exist in the project root.

Download the latest release from [encounter/objdiff](https://github.com/encounter/objdiff). Under project settings, set `Project directory`. The configuration should be loaded automatically.

Select an object from the left sidebar to begin diffing. Changes to the project will rebuild automatically: changes to source files, headers, `configure.py`, `splits.txt` or `symbols.txt`.

![](assets/objdiff.png)
