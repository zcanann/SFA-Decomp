#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283E4C.h"

extern undefined4 DAT_803dd280;
extern undefined4 DAT_803dd288;
extern undefined4 DAT_803defc4;
extern undefined4 DAT_803deff0;
extern void aramSyncTransferQueue(void);
extern void* aramStoreData(void* ptr, u32 size);
extern void aramRemoveData(void* ptr, u32 size);
extern u32 dspHRTFOn;
extern u8 *dspVoice;
extern void *(*gSalMallocHook)(u32 size);
extern void (*gSalFreeHook)(void *ptr);

/*
 * --INFO--
 *
 * Function: hwSaveSample
 * EN v1.0 Address: 0x80283DFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283E4C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwSaveSample(u32 **sample, void **ptr)
{
  u32 size;
  s32 type;
  u32 adjusted;
  u32 header;

  header = (*sample)[1];
  type = header >> 24;
  size = header & 0xffffff;
  if (type != 3) {
    if (type < 3) {
      if (type >= 2) goto size_double;
      if (type >= 0) goto size_adpcm;
      goto save;
    } else if (type >= 6) {
      goto save;
    }
  size_adpcm:
    adjusted = size + 0xd;
    size = (adjusted / 7 * 4) & ~7;
    goto save;
  size_double:
    size <<= 1;
  }
save:
  *ptr = aramStoreData(*ptr, size);
}

/*
 * --INFO--
 *
 * Function: hwRemoveSample
 * EN v1.0 Address: 0x80283E04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283EEC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwRemoveSample(u32 *sample, void *ptr)
{
  u32 size;
  s32 type;
  u32 adjusted;
  u32 header;

  header = sample[1];
  type = header >> 24;
  size = header & 0xffffff;
  if (type != 3) {
    if (type < 3) {
      if (type >= 2) goto size_double;
      if (type >= 0) goto size_adpcm;
      goto remove;
    } else if (type >= 6) {
      goto remove;
    }
  size_adpcm:
    adjusted = size + 0xd;
    size = (adjusted / 7 * 4) & ~7;
    goto remove;
  size_double:
    size <<= 1;
  }
remove:
  aramRemoveData(ptr, size);
}

/*
 * --INFO--
 *
 * Function: hwSyncSampleMem
 * EN v1.0 Address: 0x80283E08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283F18
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwSyncSampleMem(void)
{
  aramSyncTransferQueue();
}

/* Pattern wrappers. */
void hwFrameDone(void) {}

void sndSetHooks(SalHooks *hooks)
{
  gSalMallocHook = hooks->mallocHook;
  gSalFreeHook = hooks->freeHook;
}

void hwDisableHRTF(void)
{
  dspHRTFOn = 0;
}

int hwGetVirtualSampleID(int slot)
{
  u8 *entry;

  slot *= 0xf4;
  entry = dspVoice;
  entry += slot;
  if (entry[0xec] == 0) {
    return -1;
  }
  return *(int *)(entry + 0xe8);
}

int hwVoiceInStartup(int slot)
{
  u8 *entry;

  slot *= 0xf4;
  entry = dspVoice;
  entry += slot;
  return entry[0xec] == 1;
}
