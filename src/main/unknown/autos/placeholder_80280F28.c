#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80280F28.h"

extern int hwInit(void *params, u8 voiceCount, u8 streamCount, u8 stereo, void *aux1, void *aux2, u32 sampleRate);
extern void fn_80275260(int p1, void *p2);
extern void fn_8026F30C(void);
extern void synthInit(int sampleRate, void *p2);
extern void fn_80272EA4(void);
extern void fn_8027ACB8(void);
extern void fn_8027B420(void);
extern void fn_80280FFC(u32 flags);

extern u8 lbl_803BD150[];
extern u8 gSynthInitialized;
extern u8 lbl_803DE270;
extern u32 lbl_803DE350;
extern u32 lbl_803DE354;
extern u32 lbl_803DE358;
extern u32 lbl_803DE35C;
extern u32 lbl_803DE360;
extern u32 lbl_803DE364;
extern u8 lbl_803DE368;
extern u8 lbl_803DE369;
extern u8 lbl_803DE36A;

/*
 * fn_80280C30 - large state-table init not implemented here; stubbed
 * so that any cross-file callers link.
 */
#pragma dont_inline on
void fn_80280C30(void)
{
}
#pragma dont_inline reset

/*
 * Reset misc synth state and store a "stereo" flag.
 *
 * EN v1.0 Address: 0x80280BD8
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80280FFC
 * EN v1.1 Size: 68b
 */
void fn_80280FFC(u32 flags)
{
    u8 stereo = (flags & 0x2) ? 1 : 0;
    lbl_803DE354 = 0;
    lbl_803DE358 = 0;
    lbl_803DE35C = 0;
    lbl_803DE360 = 0;
    lbl_803DE364 = 0;
    lbl_803DE368 = 1;
    lbl_803DE369 = 3;
    lbl_803DE350 = 0;
    lbl_803DE36A = stereo;
}

/*
 * Empty stub.
 *
 * EN v1.1 Address: 0x80281040
 */
void fn_80281040(void)
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
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, void *p7, u32 flags)
{
    u32 sampleRate;
    void *params;

    gSynthInitialized = 0;
    if (voiceCount > 0x40) {
        lbl_803BD150[0x210] = 0x40;
    } else {
        lbl_803BD150[0x210] = voiceCount;
    }
    if (stereo > 0x8) {
        lbl_803BD150[0x213] = 0x8;
    } else {
        lbl_803BD150[0x213] = stereo;
    }
    lbl_803BD150[0x211] = streamCount;
    lbl_803BD150[0x212] = unk5;
    sampleRate = 0x7d00;
    if (hwInit(&sampleRate, lbl_803BD150[0x210], streamCount, lbl_803BD150[0x213], NULL, p7, sampleRate) != 0) {
        return 0;
    }
    {
        u8 voiceCountSnapshot = lbl_803BD150[0x210];
        fn_8027B420();
        fn_80275260(0, p7);
        fn_8026F30C();
        lbl_803DE270 = 0;
        synthInit(0x7d00, &voiceCountSnapshot);
        fn_80272EA4();
        fn_8027ACB8();
        fn_80280FFC(flags);
        gSynthInitialized = 1;
    }
    return 0;
}
