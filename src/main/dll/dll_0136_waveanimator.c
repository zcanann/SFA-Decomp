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
 *
 * FUN_80192488 re-tints the active map block's vertex colors against the
 * per-cell color field, gating two map ids (0x49b2f / 0x49b67) on a game
 * bit before recoloring already-claimed vertices.
 */
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/dll/groundanimator_state.h"
#include "main/game_object.h"

/* Layout overlay used by waveanimator_modelMtxFn (flags + dispatch args). */
typedef struct WaveanimatorState
{
    u8 pad0[0x34 - 0x0];
    u8 unk34;
    u8 pad35[0x36 - 0x35];
    u8 unk36;
    u8 unk37;
    u8 unk38;
    u8 pad39[0x3c - 0x39];
} WaveanimatorState;

STATIC_ASSERT(sizeof(WaveanimatorState) == 0x3C);

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(f32);
extern void mm_free(void* p);
extern void* mmAlloc(int size, int align, int tag);
extern f32 mathSinf(f32);
extern int FUN_80017af0();
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int* obj, int group);
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

/* shared wave tables (built once per first instance, freed with the last) */
extern u8 lbl_803DDAE8;     /* live-instance refcount */
extern void* lbl_803DDAEC;  /* per-cell RGB color field */
extern void* lbl_803DDAF0;  /* per-grid phase table */
extern void* lbl_803DDAF4;  /* per-cell height field */
extern u8 lbl_803DDAF8;     /* phases-advanced-this-frame latch */
extern u8 framesThisStep;

/* wave-geometry and color-ramp constants */
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
void alphaanimator_hitDetect(void);
int alphaanimator_getExtraSize(void);
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void waveanimator_modelMtxFn(int obj, int a, int b, int c)
{
    int* state = ((GameObject*)obj)->extra;
    u32 v;
    v = (u32)((WaveanimatorState*)state)->unk34 | 4;
    ((WaveanimatorState*)state)->unk34 = (u8)v;
    ((WaveanimatorState*)state)->unk36 = (u8)a;
    ((WaveanimatorState*)state)->unk37 = (u8)b;
    ((WaveanimatorState*)state)->unk38 = (u8)c;
}

void waveanimator_func0B(int* obj)
{
    WaveAnimatorState* state = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    state->flags |= 2;
}

#pragma scheduling on
#pragma peephole on
void FUN_80192488(void)
{
    int texV;
    int ctxHi;
    int block;
    int polyIdx;
    int cell;
    uint gameBit;
    int texU;
    int ctxLo;
    int mapId;
    int placement;
    int vtxIdx;
    int vtx;
    undefined8 pair;

    pair = FUN_8028682c();
    ctxHi = (int)((ulonglong)pair >> 0x20);
    ctxLo = (int)pair;
    placement = *(int*)(ctxHi + 0x4c);
    block = FUN_8005b398((double)*(float*)(ctxHi + 0xc), (double)*(float*)(ctxHi + 0x10));
    block = FUN_8005af70(block);
    if (block == 0)
    {
        *(undefined*)(ctxLo + 0x10) = 1;
    }
    else
    {
        polyIdx = FUN_80017af0(0xe);
        if ((polyIdx != 0) &&
            (placement = FUN_8005337c(-*(int*)(polyIdx + *(short*)(placement + 0x18) * 4)), placement != 0))
        {
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx++)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx++)
                {
                    if (*(int*)(vtx + 0x24) == placement)
                    {
                        texU = (uint) * (ushort*)(placement + 10) << 6;
                        texV = (uint) * (ushort*)(placement + 0xc) << 6;
                        if (*(byte*)(vtx + 0x2a) == 0xff)
                        {
                            texU = FUN_80056448((int)*(char*)(ctxLo + 0x11), (int)*(char*)(ctxLo + 0x12), texU,
                                                 texV);
                            *(char*)(vtx + 0x2a) = (char)texU;
                        }
                        else
                        {
                            mapId = *(int*)(*(int*)(ctxHi + 0x4c) + 0x14);
                            if ((mapId == 0x49b2f) || (mapId == 0x49b67))
                            {
                                gameBit = GameBit_Get(*(uint*)(ctxLo + 8));
                                if (gameBit != 0)
                                {
                                    FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                                 (int)*(char*)(ctxLo + 0x12), texU, texV);
                                }
                            }
                            else
                            {
                                FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                             (int)*(char*)(ctxLo + 0x12), texU, texV);
                            }
                        }
                    }
                    vtx = vtx + 8;
                }
            }
        }
    }
    FUN_80286878();
}
#pragma reset

void waveanimator_update(void)
{
}

void waveanimator_release(void)
{
}

void waveanimator_initialise(void)
{
}

int waveanimator_getExtraSize(void) { return sizeof(WaveAnimatorState); }
int waveanimator_getObjectTypeId(void) { return 0x0; }

#pragma peephole off
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F70);
}
#pragma reset

void waveanimator_setScale(int* obj, f32 fval)
{
    WaveAnimatorState* state = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    state->flags |= 1;
    state->scaleB = fval;
}

#pragma scheduling off
void waveanimator_init(int* obj, int* desc)
{
    WaveAnimatorState* vstate = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    f32 scale;
    vstate->unk18 = ((WaveanimatorObjectDef*)desc)->unk20;
    vstate->originX = ((WaveanimatorObjectDef*)desc)->originX;
    vstate->originY = ((WaveanimatorObjectDef*)desc)->originY;
    vstate->spanX = ((WaveanimatorObjectDef*)desc)->spanX;
    vstate->spanY = ((WaveanimatorObjectDef*)desc)->spanY;
    vstate->ampX = (f32) * (s8*)((char*)desc + 0x1E);
    vstate->ampY = (f32) * (s8*)((char*)desc + 0x1F);
    vstate->period = ((WaveanimatorObjectDef*)desc)->period;
    vstate->gridN = ((WaveanimatorObjectDef*)desc)->gridN;
    scale = lbl_803E3F70;
    vstate->scaleA = scale;
    vstate->scaleB = scale;
    if (lbl_803DDAE8 == 0)
    {
        fn_801923F8((int*)vstate);
    }
    ObjGroup_AddObject(obj, 27);
    lbl_803DDAE8++;
}
#pragma reset

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

void waveanimator_hitDetect(int* obj)
{
    int i;
    int j;
    int phaseIdx;
    WaveAnimatorState* cfg;
    if (lbl_803DDAF8 != 0)
    {
        return;
    }
    cfg = (WaveAnimatorState*)((GameObject*)obj)->extra;
    phaseIdx = 0;
    for (i = 0; i < cfg->gridN; i++)
    {
        for (j = 0; j < cfg->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[phaseIdx] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[phaseIdx] >= cfg->period)
            {
                ((s16*)lbl_803DDAF0)[phaseIdx] -= cfg->period;
            }
            ((s16*)lbl_803DDAF0)[phaseIdx + 1] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[phaseIdx + 1] >= cfg->period)
            {
                ((s16*)lbl_803DDAF0)[phaseIdx + 1] -= cfg->period;
            }
            phaseIdx += 2;
        }
    }
    lbl_803DDAF8 = 1;
}

void fn_801923F8(int* cfgArg)
{
    int i;
    int j;
    int x;
    int stepX;
    int y;
    int stepY;
    int heightIdx;
    int colorSrcIdx;
    int colorIdx;
    int phaseIdx;
    f32 waveScale;
    f32 waveDivisor;
    f32 z;
    WaveAnimatorState* cfg = (WaveAnimatorState*)cfgArg;

    lbl_803DDAF4 = mmAlloc(4 * cfg->period * cfg->period, 0xFFFFFF, 0);
    lbl_803DDAEC = mmAlloc(3 * cfg->period * cfg->period, 0xFFFFFF, 0);

    x = cfg->originX;
    stepX = (s32)((lbl_803E3F40 * (f32)cfg->spanX) / (f32)cfg->period);
    y = cfg->originY;
    stepY = (s32)((lbl_803E3F40 * (f32)cfg->spanY) / (f32)cfg->period);

    z = lbl_803E3F44;
    cfg->maxHeight = z;
    cfg->minHeight = z;

    heightIdx = 0;
    waveScale = lbl_803E3F48;
    waveDivisor = lbl_803E3F4C;
    for (i = 0; i < cfg->period; i++)
    {
        f32 xv = waveScale * (f32)x;
        for (j = 0; j < cfg->period; j++)
        {
            f32 s1 = mathSinf((waveScale * (f32)y) / waveDivisor);
            f32 a = cfg->ampY * s1;
            f32 s2 = mathSinf(xv / waveDivisor);
            ((f32*)lbl_803DDAF4)[heightIdx] = cfg->ampX * s2 + a;
            if (((f32*)lbl_803DDAF4)[heightIdx] < cfg->minHeight)
            {
                cfg->minHeight = ((f32*)lbl_803DDAF4)[heightIdx];
            }
            if (((f32*)lbl_803DDAF4)[heightIdx] > cfg->maxHeight)
            {
                cfg->maxHeight = ((f32*)lbl_803DDAF4)[heightIdx];
            }
            y += stepY;
            heightIdx++;
        }
        x += stepX;
    }

    {
        f32 negMin = -cfg->minHeight;
        f32 colorSplitZero;
        colorSrcIdx = 0;
        colorIdx = 0;
        colorSplitZero = lbl_803E3F44;
        for (i = 0; i < cfg->period; i++)
        {
            for (j = 0; j < cfg->period; j++)
            {
                f32 v = ((f32*)lbl_803DDAF4)[colorSrcIdx];
                if (v < colorSplitZero)
                {
                    f32 t = (v - cfg->minHeight) / negMin;
                    ((s8*)lbl_803DDAEC)[colorIdx] = (s32)(lbl_803E3F54 * t + lbl_803E3F50);
                    ((s8*)lbl_803DDAEC)[colorIdx + 1] = (s32)(lbl_803E3F5C * t + lbl_803E3F58);
                    ((s8*)lbl_803DDAEC)[colorIdx + 2] = (s32)(lbl_803E3F64 * t + lbl_803E3F60);
                }
                else
                {
                    ((s8*)lbl_803DDAEC)[colorIdx] = 255;
                    ((s8*)lbl_803DDAEC)[colorIdx + 1] = 255;
                    ((s8*)lbl_803DDAEC)[colorIdx + 2] = 255;
                }
                colorSrcIdx++;
                colorIdx += 3;
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
