#include "main/audio/hw_stream.h"

#include "main/audio/dsp_voice_state.h"
#include "main/audio/hw_dspctrl.h"
#include "main/audio/aram.h"
#include "dolphin/os/OSCache.h"

extern DSPstudioinfo dspStudio[8];

u32 hwRemoveInput(u8 studio, SND_STUDIO_INPUT* input)
{
    return salRemoveStudioInput(&dspStudio[studio], input);
}

u32 hwChangeStudio(u32 slot)
{
    int mode;
    u32 pos;
    u32 lowBits;
    int samplePos;
    DSPvoice* voice;
    DSPvoice* curVoice;

    voice = &dspVoice[slot];
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
        curVoice = (DSPvoice*)((u8*)dspVoice + slot * 0xf4);
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

void hwGetPos(void* buffer, u32 streamPos, u32 byteCount, u8 streamHandle, void (*callback)(u32), u32 callbackArg)
{
    u32 offset;
    u8* addr;
    u32 streamLength;

    addr = buffer;
    offset = aramGetStreamBufferAddress(streamHandle, &streamLength);
    byteCount += streamPos & 0x1f;
    streamPos &= 0xffffffe0;
    byteCount = (byteCount + 0x1f) & ~0x1f;
    addr += streamPos;
    DCStoreRange(addr, byteCount);
    aramUploadData(addr, offset + streamPos, byteCount, 1, callback, callbackArg);
}

void* hwFlushStream(u8 streamHandle)
{
    return (void*)aramGetStreamBufferAddress(streamHandle, 0);
}

void* hwTransAddr(void* samples)
{
    return samples;
}
