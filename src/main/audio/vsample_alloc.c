#include "main/audio/synth_virtual_sample.h"
#include "main/audio/aram.h"

typedef struct VsInfo
{
    u16 smpID;
    u16 instID;
    u32 start;
    u32 size;
    u32 wrapA;
    u32 wrapB;
} VsInfo;

typedef struct VsBuffer
{
    u8 state;
    u8 pad01;
    u8 smpType;
    u8 voice;
    u32 last;
    u8 pad08[0x10 - 0x8];
    VsInfo info;
} VsBuffer;

typedef struct VS
{
    u8 numBuffers;
    u8 pad01[3];
    u32 bufferLength;
    VsBuffer streamBuffer[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u8 voices[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u16 nextInstID;
    u8 pad94a[2];
    int (*callback)(int kind, void* data);
} VS;

extern u8 synthVirtualSampleState[];

/*
 * vsInit - reset the virtual sample stream buffer table.
 *
 * EN v1.1 Address: 0x8027ACB8, size 288b
 */
void synthInitVirtualSampleTable(void)
{
    int i;
    VS* v = (VS*)synthVirtualSampleState;

    v->numBuffers = 0;
    for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++)
    {
        v->voices[i] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
    }
    v->nextInstID = 0;
    v->callback = 0;
}

static void vsFreeBuffer(VS* v, u8 bufferIndex)
{
    v->streamBuffer[bufferIndex].state = 0;
    v->voices[v->streamBuffer[bufferIndex].voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static u8 vsAllocateBuffer(VS* v)
{
    u8 i;

    for (i = 0; i < v->numBuffers; ++i)
    {
        if (v->streamBuffer[i].state != 0)
        {
            continue;
        }
        v->streamBuffer[i].state = 1;
        v->streamBuffer[i].last = 0;
        return i;
    }

    return SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static u16 vsNewInstanceID(VS* v)
{
    u8 i;
    u16 instID;

    do
    {
        instID = v->nextInstID++;
        for (i = 0; i < v->numBuffers; ++i)
        {
            if (v->streamBuffer[i].state != 0 && v->streamBuffer[i].info.instID == instID)
            {
                break;
            }
        }
    }
    while (i != v->numBuffers);

    return instID;
}

/*
 * vsSampleStartNotify - allocate a stream buffer for the voice and set up
 * its virtual sample loop buffer.
 */
u32 synthClaimVirtualSampleSlot(u8 voiceID)
{
    VS* v = (VS*)synthVirtualSampleState;
    u8 sb;
    u8 i;
    u32 addr;

    for (i = 0; i < v->numBuffers; ++i)
    {
        if (v->streamBuffer[i].state != 0 && v->streamBuffer[i].voice == voiceID)
        {
            vsFreeBuffer(v, i);
        }
    }

    sb = v->voices[voiceID] = vsAllocateBuffer(v);
    if (sb != SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
    {
        addr = aramGetStreamBufferAddress(v->voices[voiceID], 0);
        hwSetVirtualSampleLoopBuffer(voiceID, addr, v->bufferLength);
        v->streamBuffer[sb].info.smpID = hwGetSampleID(voiceID);
        v->streamBuffer[sb].info.instID = vsNewInstanceID(v);
        v->streamBuffer[sb].smpType = hwGetSampleType(voiceID);
        v->streamBuffer[sb].voice = voiceID;
        if (v->callback != 0)
        {
            v->callback(SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND, &v->streamBuffer[sb].info);
            return (v->streamBuffer[sb].info.instID << 8) | (voiceID & 0xff);
        }
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }
    else
    {
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }

    return SYNTH_VIRTUAL_SAMPLE_INVALID_ID;
}
