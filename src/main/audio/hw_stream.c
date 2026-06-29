#include "main/audio/hw_stream.h"
#include "main/audio/dsp_voice.h"
#include "main/engine_shared.h"
extern void salRemoveStudioInput(void* p, void* input);
extern int aramGetStreamBufferAddress(int stream, void* out);
extern void aramUploadData(int dest, int src, u32 size, int mode, u32 callback,
                           u32 callbackArg);

extern u8 lbl_803CC1E0[];
extern u8* dspVoice;

void hwRemoveInput(u32 idx, void* input)
{
    u32 offset = (idx & 0xff) * 0xbc;
    salRemoveStudioInput(lbl_803CC1E0 + offset, input);
}

#pragma optimization_level 1
int hwChangeStudio(int slot)
{
    int mode;
    u32 pos;
    u32 lowBits;
    int samplePos;
    DSPvoice* voice;
    DSPvoice* curVoice;
    int offset;
    u8* base;

    offset = slot * 0xf4;
    base = dspVoice;
    voice = (DSPvoice*)(base + offset);
    if (voice->state != 2)
    {
        return 0;
    }
    mode = voice->smp_info.compType;
    switch (mode)
    {
    case 0:
    case 1:
    case 4:
    case 5:
        curVoice = (DSPvoice*)(base + offset);
        pos = curVoice->currentAddr;
        samplePos = ((pos - 2 * *(int*)&curVoice->smp_info.addr) >> 4) * 0xe;
        lowBits = pos & 0xf;
        if (lowBits < 2)
        {
            return samplePos;
        }
        samplePos = lowBits + samplePos;
        return samplePos - 2;
    case 3:
        return (int)voice->currentAddr - *(int*)&voice->smp_info.addr;
    case 2:
        return (int)voice->currentAddr - (*(u32*)&voice->smp_info.addr >> 1);
    default:
        return slot;
    }
}
#pragma optimization_level reset

void hwGetPos(int dest, u32 streamPos, int byteCount, int stream, u32 callback,
              u32 callbackArg)
{
    int uploadDest;
    int uploadSize;
    u32 uploadCallbackArg;
    u32 uploadCallback;
    u32 size;
    int offset;
    u8 stack[8];

    uploadDest = dest;
    uploadSize = byteCount;
    uploadCallback = callback;
    uploadCallbackArg = callbackArg;
    offset = aramGetStreamBufferAddress(stream, stack);
    uploadSize += streamPos & 0x1f;
    streamPos &= 0xffffffe0;
    size = (uploadSize + 0x1f) & ~0x1f;
    uploadDest += streamPos;
    DCStoreRange((void*)uploadDest, size);
    aramUploadData(uploadDest, offset + streamPos, size, 1, uploadCallback, uploadCallbackArg);
}

void hwFlushStream(int stream)
{
    aramGetStreamBufferAddress(stream, 0);
}

void hwInitStream(void)
{
}
