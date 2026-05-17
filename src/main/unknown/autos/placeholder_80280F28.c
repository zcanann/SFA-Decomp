#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80280F28.h"

extern int hwInit(u32 *sampleRate, u8 voiceCount, u8 maxStudios, u32 flags);
extern void dataInit(int p1, void *p2);
extern void fn_8026F30C(void);
extern void synthInit(u32 sampleRate, u32 voiceCount);
extern void synthInitJobTable(void);
extern void synthInitVirtualSampleTable(void);
extern void synthResetLoadedGroupCount(void);
extern void s3dInit(u32 flags);

extern u8 lbl_803BD150[];
extern u8 gSynthInitialized;
extern u8 synthIdleWaitActive;
extern u8 s3dCallCnt;
extern u32 s3dEmitterRoot;
extern u32 s3dListenerRoot;
extern u32 s3dRoomRoot;
extern u32 s3dDoorRoot;
extern u32 snd_used_studios;
extern u8 snd_base_studio;
extern u8 snd_max_studios;
extern u8 lbl_803DE36A;

/*
 * 3D sound emitter/listener update. Stubbed so cross-file callers link.
 */
#pragma dont_inline on
void s3dHandle(void)
{
}
#pragma dont_inline reset

/*
 * Reset 3D sound bookkeeping and store a stereo flag.
 *
 * EN v1.0 Address: 0x80280BD8
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80280FFC
 * EN v1.1 Size: 68b
 */
#pragma dont_inline on
void s3dInit(u32 flags)
{
    u8 stereo = (flags & 0x2) != 0;
    s3dEmitterRoot = 0;
    s3dListenerRoot = 0;
    s3dRoomRoot = 0;
    s3dDoorRoot = 0;
    snd_used_studios = 0;
    snd_base_studio = 1;
    snd_max_studios = 3;
    s3dCallCnt = 0;
    lbl_803DE36A = stereo;
}
#pragma dont_inline reset

/*
 * Empty stub.
 *
 * EN v1.1 Address: 0x80281040
 */
void s3dExit(void)
{
}

/*
 * Sound init: clamps voice/stream counts, calls hwInit, then walks
 * a chain of subsystem inits if hwInit succeeded; sets the
 * gSynthInitialized flag last.
 *
 * EN v1.0 Address: 0x80280BDC
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80281044
 * EN v1.1 Size: 280b
 */
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void *data)
{
    u32 sampleRate[4];
    int result;

    gSynthInitialized = 0;
    if (voiceCount <= 0x40) {
        lbl_803BD150[0x210] = voiceCount;
    } else {
        lbl_803BD150[0x210] = 0x40;
    }
    if (stereo <= 0x8) {
        lbl_803BD150[0x213] = stereo;
    } else {
        lbl_803BD150[0x213] = 0x8;
    }
    lbl_803BD150[0x211] = streamCount;
    lbl_803BD150[0x212] = unk5;
    sampleRate[3] = 0x7d00;
    result = hwInit(&sampleRate[3], lbl_803BD150[0x210], lbl_803BD150[0x213], flags);
    if (result == 0) {
        u8 voiceCountSnapshot = lbl_803BD150[0x210];
        synthResetLoadedGroupCount();
        dataInit(0, data);
        fn_8026F30C();
        synthIdleWaitActive = 0;
        synthInit(0x7d00, voiceCountSnapshot);
        synthInitJobTable();
        synthInitVirtualSampleTable();
        s3dInit(flags);
        gSynthInitialized = 1;
        result = 0;
    }
    return result;
}
