#include "main/audio/hw_samplemem.h"

#pragma exceptions on

extern u32 dspHRTFOn;
extern u8* dspVoice;
extern void*(*gSalMallocHook)(u32 size);

void hwSaveSample(u32** sample, void** ptr)
{
    u32 size;
    s32 type;
    u32 adjusted;
    u32 header;

    header = (*sample)[1];
    type = header >> 24;
    size = header & 0xffffff;
    if (type != 3)
    {
        if (type < 3)
        {
            if (type >= 2) goto size_double;
            if (type >= 0) goto size_adpcm;
            goto save;
        }
        else if (type >= 6)
        {
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
    *ptr = (void*)aramStoreData(*ptr, size);
}

void hwRemoveSample(u32* sample, void* ptr)
{
    u32 size;
    s32 type;
    u32 adjusted;
    u32 header;

    header = sample[1];
    type = header >> 24;
    size = header & 0xffffff;
    if (type != 3)
    {
        if (type < 3)
        {
            if (type >= 2) goto size_double;
            if (type >= 0) goto size_adpcm;
            goto remove;
        }
        else if (type >= 6)
        {
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

void hwSyncSampleMem(void)
{
    aramSyncTransferQueue();
}

void hwFrameDone(void)
{
}

void sndSetHooks(const SalHooks* hooks)
{
    *(SalHooks*)&gSalMallocHook = *hooks;
}

void hwDisableHRTF(void)
{
    dspHRTFOn = 0;
}

int hwGetVirtualSampleID(int slot)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    if (entry[0xec] == 0)
    {
        return -1;
    }
    return *(int*)(entry + 0xe8);
}

int hwVoiceInStartup(int slot)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    return entry[0xec] == 1;
}
