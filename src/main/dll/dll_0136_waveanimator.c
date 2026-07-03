/*
 * waveanimator (DLL 0x136) - drives a procedurally rippling water/wave
 * surface for a map object. On init it folds the object's placement def
 * (origin/span/amplitude/period/grid) into a shared WaveAnimatorState and,
 * for the first instance only, builds three globally shared tables via
 * fn_801923F8: a per-cell height field (lbl_803DDAF4), a per-cell RGB
 * color field shaded by height (lbl_803DDAEC), and a per-grid phase table
 * (lbl_803DDAF0). hitDetect advances every phase by framesThisStep/2 each
 * step (wrapping at the wave period); the tables are freed when the last
 * instance is destroyed (lbl_803DDAE8 is the live-instance refcount).
 */
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
#include "main/mm.h"

/*
 * Field overlay used by waveanimator_modelMtxFn: 0x34 is WaveAnimatorState.flags,
 * 0x36-0x38 are the three dispatch args stored into pad35[1..3].
 */
typedef struct WaveanimatorModelMtxCtx
{
    u8 pad0[0x34 - 0x0];
    u8 flags;
    u8 pad35[0x36 - 0x35];
    u8 arg0;
    u8 arg1;
    u8 arg2;
    u8 pad39[0x3c - 0x39];
} WaveanimatorModelMtxCtx;

STATIC_ASSERT(sizeof(WaveanimatorModelMtxCtx) == 0x3C);

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

extern float mathSinf(float x);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int* obj, int group);
extern u8 lbl_803DDAE8;     /* live-instance refcount */
extern void* lbl_803DDAEC;  /* per-cell RGB color field */
extern void* lbl_803DDAF0;  /* per-grid phase table */
extern void* lbl_803DDAF4;  /* per-cell height field */
extern u8 lbl_803DDAF8;     /* phases-advanced-this-frame latch */
extern f32 lbl_803E3F40; /* grid step scale */
extern f32 lbl_803E3F44; /* 0.0f sentinel / color-split zero */
extern f32 lbl_803E3F48; /* wave scale */
extern f32 lbl_803E3F4C; /* wave divisor */
extern f32 lbl_803E3F50; /* R ramp base */
extern f32 lbl_803E3F54; /* R ramp slope */
extern f32 lbl_803E3F58; /* G ramp base */
extern f32 lbl_803E3F5C; /* G ramp slope */
extern f32 lbl_803E3F60; /* B ramp base */
extern f32 lbl_803E3F64; /* B ramp slope */
extern f32 lbl_803E3F70; /* model scale */

void fn_801923F8(int* cfgArg);

void waveanimator_modelMtxFn(int obj, int a, int b, int c)
{
    int* state = ((GameObject*)obj)->extra;
    u32 v;
    v = (u32)((WaveanimatorModelMtxCtx*)state)->flags | 4;
    ((WaveanimatorModelMtxCtx*)state)->flags = v;
    ((WaveanimatorModelMtxCtx*)state)->arg0 = a;
    ((WaveanimatorModelMtxCtx*)state)->arg1 = b;
    ((WaveanimatorModelMtxCtx*)state)->arg2 = c;
}

void waveanimator_func0B(int* obj)
{
    WaveAnimatorState* state = (WaveAnimatorState*)(int*)((GameObject*)obj)->extra;
    state->flags |= 2;
}

void waveanimator_setScale(int* obj, f32 fval)
{
    WaveAnimatorState* state = (WaveAnimatorState*)(int*)((GameObject*)obj)->extra;
    state->flags |= 1;
    state->scaleB = fval;
}

void fn_801923F8(int* cfgArg)
{
    int row;
    int heightIdx;
    int i;
    int j;
    int x;
    int stepX;
    int y;
    int phaseIdx;
    int stepY;
    f32 a;
    f32 waveDivisor;
    f32 waveScale;
    f32 z;
    WaveAnimatorState* cfg = (WaveAnimatorState*)cfgArg;

    lbl_803DDAF4 = mmAlloc(4 * cfg->period * cfg->period, 0xFFFFFF, 0);
    lbl_803DDAEC = mmAlloc(3 * cfg->period * cfg->period, 0xFFFFFF, 0);

    x = cfg->originX;
    stepX = (s32)((lbl_803E3F40 * cfg->spanX) / cfg->period);
    y = cfg->originY;
    stepY = (s32)((lbl_803E3F40 * cfg->spanY) / cfg->period);

    z = lbl_803E3F44;
    cfg->maxHeight = z;
    cfg->minHeight = z;

    i = 0;
    heightIdx = 0;
    waveScale = lbl_803E3F48;
    waveDivisor = lbl_803E3F4C;
    for (; i < cfg->period; i++)
    {
        f32 xv;
        j = 0;
        row = heightIdx;
        xv = waveScale * x;
        for (; j < cfg->period; j++)
        {
            f32 s1 = mathSinf((waveScale * y) / waveDivisor);
            f32 s2;
            a = cfg->ampY * s1;
            s2 = mathSinf(xv / waveDivisor);
            *(f32*)((u8*)lbl_803DDAF4 + row) = cfg->ampX * s2 + a;
            if (*(f32*)((u8*)lbl_803DDAF4 + row) < cfg->minHeight)
            {
                cfg->minHeight = *(f32*)((u8*)lbl_803DDAF4 + row);
            }
            if (*(f32*)((u8*)lbl_803DDAF4 + row) > cfg->maxHeight)
            {
                cfg->maxHeight = *(f32*)((u8*)lbl_803DDAF4 + row);
            }
            y += stepY;
            row += 4;
            heightIdx += 4;
        }
        x += stepX;
    }

    {
        f32 colorSplitZero;
        f32 negMin = -cfg->minHeight;
        i = 0;
        heightIdx = i;
        x = i;
        colorSplitZero = lbl_803E3F44;
        for (; i < cfg->period; i++)
        {
            int src;
            int byte;
            for (j = 0, src = heightIdx, byte = x; j < cfg->period; src += 4, byte += 3, heightIdx += 4, x += 3, j++)
            {
                f32 v = *(f32*)((u8*)lbl_803DDAF4 + src);
                if (v < colorSplitZero)
                {
                    f32 t = (v - cfg->minHeight) / negMin;
                    *(u8*)((u8*)lbl_803DDAEC + byte) = lbl_803E3F54 * t + lbl_803E3F50;
                    *(u8*)((u8*)lbl_803DDAEC + byte + 1) = lbl_803E3F5C * t + lbl_803E3F58;
                    *(u8*)((u8*)lbl_803DDAEC + byte + 2) = lbl_803E3F64 * t + lbl_803E3F60;
                }
                else
                {
                    *(u8*)((u8*)lbl_803DDAEC + byte) = 255;
                    *(u8*)((u8*)lbl_803DDAEC + byte + 1) = 255;
                    *(u8*)((u8*)lbl_803DDAEC + byte + 2) = 255;
                }
            }
        }
    }

    lbl_803DDAF0 = mmAlloc(4 * cfg->gridN * cfg->gridN, 0xFFFFFF, 0);
    phaseIdx = 0;
    for (i = 0; i < cfg->gridN; i++)
    {
        for (j = 0; j < cfg->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[phaseIdx] = (s16)(i * 10);
            ((s16*)lbl_803DDAF0)[phaseIdx + 1] = (s16)(j * 10);
            phaseIdx += 2;
        }
    }
}

int waveanimator_getExtraSize(void) { return sizeof(WaveAnimatorState); }
int waveanimator_getObjectTypeId(void) { return 0x0; }

void waveanimator_free(int* obj)
{
    if (--lbl_803DDAE8 == 0)
    {
        if (lbl_803DDAF4 != NULL) mm_free(lbl_803DDAF4);
        if (lbl_803DDAF0 != NULL) mm_free(lbl_803DDAF0);
        if (lbl_803DDAEC != NULL) mm_free(lbl_803DDAEC);
    }
    ObjGroup_RemoveObject(obj, 27);
}

void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F70);
}

void waveanimator_hitDetect(int* obj)
{
    int i;
    int j;
    int phaseIdx;
    WaveAnimatorState* state;
    if (lbl_803DDAF8 != 0)
    {
        return;
    }
    state = (WaveAnimatorState*)((GameObject*)obj)->extra;
    phaseIdx = 0;
    for (i = 0; i < state->gridN; i++)
    {
        for (j = 0; j < state->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[phaseIdx] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[phaseIdx] >= state->period)
            {
                ((s16*)lbl_803DDAF0)[phaseIdx] -= state->period;
            }
            ((s16*)lbl_803DDAF0)[phaseIdx + 1] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[phaseIdx + 1] >= state->period)
            {
                ((s16*)lbl_803DDAF0)[phaseIdx + 1] -= state->period;
            }
            phaseIdx += 2;
        }
    }
    lbl_803DDAF8 = 1;
}

void waveanimator_update(void)
{
}

void waveanimator_init(int* obj, int* desc)
{
    WaveAnimatorState* state = (WaveAnimatorState*)(int*)((GameObject*)obj)->extra;
    f32 scale;
    state->sinkDepthScale = ((WaveanimatorObjectDef*)desc)->sinkDepthScale;
    state->originX = ((WaveanimatorObjectDef*)desc)->originX;
    state->originY = ((WaveanimatorObjectDef*)desc)->originY;
    state->spanX = ((WaveanimatorObjectDef*)desc)->spanX;
    state->spanY = ((WaveanimatorObjectDef*)desc)->spanY;
    state->ampX = (f32)((WaveanimatorObjectDef*)desc)->ampX;
    state->ampY = (f32)((WaveanimatorObjectDef*)desc)->ampY;
    state->period = ((WaveanimatorObjectDef*)desc)->period;
    state->gridN = ((WaveanimatorObjectDef*)desc)->gridN;
    scale = lbl_803E3F70;
    state->scaleA = scale;
    state->scaleB = scale;
    if (lbl_803DDAE8 == 0)
    {
        fn_801923F8((int*)state);
    }
    ObjGroup_AddObject(obj, 27);
    lbl_803DDAE8++;
}

void waveanimator_release(void)
{
}

void waveanimator_initialise(void)
{
}
