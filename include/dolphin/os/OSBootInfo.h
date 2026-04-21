#ifndef _DOLPHIN_OSBOOTINFO
#define _DOLPHIN_OSBOOTINFO

#include "dolphin/dvd.h"
#include "dolphin/types.h"

typedef struct OSBootInfo_s {
  DVDDiskID DVDDiskID;
  u32 magic;
  u32 version;
  u32 memorySize;
  u32 consoleType;
  void* arenaLo;
  void* arenaHi;
  void* FSTLocation;
  u32 FSTMaxLength;
} OSBootInfo;

typedef struct BI2Debug {
  s32 debugMonSize;
  s32 simMemSize;
  u32 argOffset;
  u32 debugFlag;
  int trackLocation;
  int trackSize;
  u32 countryCode;
  u8 unk[8];
  u32 padSpec;
} BI2Debug;

#define OS_BOOTINFO_MAGIC 0x0D15EA5E
#define OS_BOOTINFO_MAGIC_JTAG 0xE5207C22
#define OS_DVD_MAGIC_NINTENDO 0xC2339F3D
#define OS_THREAD_STACK_MAGIC 0xDEADBABE

#define OS_BOOTROM_ADDR ((void*)0x81300000)

#endif /* _DOLPHIN_OSBOOTINFO */
