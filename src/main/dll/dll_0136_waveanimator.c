/* DLL 0x136 - WaveAnimator [80192394-801923C4) */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"

typedef struct WaveanimatorState
{
    u8 pad0[0x34 - 0x0];
    u8 unk34;
    u8 pad35[0x36 - 0x35];
    u8 unk36;
    u8 unk37;
    u8 unk38;
    u8 pad39[0x40 - 0x39];
} WaveanimatorState;

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);
STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);
extern int FUN_80017af0();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();
extern void mm_free(void* p);
extern f32 lbl_803E3F70;
extern void fn_801923F8(int* cfg);
extern u8 lbl_803DDAE8;
extern void* lbl_803DDAEC;
extern void* lbl_803DDAF0;
extern void* lbl_803DDAF4;
extern u8 lbl_803DDAF8;
extern u8 framesThisStep;
extern void* mmAlloc(int size, int align, int tag);
extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 mathSinf(f32);

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

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

void waveanimator_func0B(int* obj)
{
    WaveAnimatorState* p = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    p->flags |= 2;
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
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx = polyIdx + 1)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx = vtxIdx + 1)
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
    return;
}

void waveanimator_update(void)
{
}

void waveanimator_release(void)
{
}

void waveanimator_initialise(void)
{
}

void alphaanimator_hitDetect(void);

int waveanimator_getExtraSize(void) { return 0x3c; }
int waveanimator_getObjectTypeId(void) { return 0x0; }
int alphaanimator_getExtraSize(void);

#pragma peephole off
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F70);
}

void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void waveanimator_setScale(int* obj, f32 fval)
{
    WaveAnimatorState* p = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    p->flags |= 1;
    p->scaleB = fval;
}

#pragma scheduling off
void waveanimator_init(int* obj, int* desc)
{
    WaveAnimatorState* vstate = (WaveAnimatorState*)((int**)obj)[0xB8 / 4];
    f32 fz;
    vstate->unk18 = ((WaveanimatorObjectDef*)desc)->unk20;
    vstate->originX = ((WaveanimatorObjectDef*)desc)->originX;
    vstate->originY = ((WaveanimatorObjectDef*)desc)->originY;
    vstate->spanX = ((WaveanimatorObjectDef*)desc)->spanX;
    vstate->spanY = ((WaveanimatorObjectDef*)desc)->spanY;
    vstate->ampX = (f32) * (s8*)((char*)desc + 0x1E);
    vstate->ampY = (f32) * (s8*)((char*)desc + 0x1F);
    vstate->period = ((WaveanimatorObjectDef*)desc)->period;
    vstate->gridN = ((WaveanimatorObjectDef*)desc)->gridN;
    fz = lbl_803E3F70;
    vstate->scaleA = fz;
    vstate->scaleB = fz;
    if (lbl_803DDAE8 == 0)
    {
        fn_801923F8((int*)vstate);
    }
    ObjGroup_AddObject(obj, 27);
    lbl_803DDAE8++;
}

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
    int off;
    WaveAnimatorState* w;
    if (lbl_803DDAF8 != 0)
    {
        return;
    }
    w = (WaveAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    off = 0;
    for (i = 0; i < w->gridN; i++)
    {
        for (j = 0; j < w->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[off] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[off] >= w->period)
            {
                ((s16*)lbl_803DDAF0)[off] -= w->period;
            }
            ((s16*)lbl_803DDAF0)[off + 1] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[off + 1] >= w->period)
            {
                ((s16*)lbl_803DDAF0)[off + 1] -= w->period;
            }
            off += 2;
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
    int flat;
    int fi;
    int bi;
    int hi;
    f32 c48;
    f32 c4C;
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

    flat = 0;
    c48 = lbl_803E3F48;
    c4C = lbl_803E3F4C;
    for (i = 0; i < cfg->period; i++)
    {
        f32 xv = c48 * (f32)x;
        for (j = 0; j < cfg->period; j++)
        {
            f32 s1 = mathSinf((c48 * (f32)y) / c4C);
            f32 a = cfg->ampY * s1;
            f32 s2 = mathSinf(xv / c4C);
            ((f32*)lbl_803DDAF4)[flat] = cfg->ampX * s2 + a;
            if (((f32*)lbl_803DDAF4)[flat] < cfg->minHeight)
            {
                cfg->minHeight = ((f32*)lbl_803DDAF4)[flat];
            }
            if (((f32*)lbl_803DDAF4)[flat] > cfg->maxHeight)
            {
                cfg->maxHeight = ((f32*)lbl_803DDAF4)[flat];
            }
            y += stepY;
            flat++;
        }
        x += stepX;
    }

    {
        f32 negMin = -cfg->minHeight;
        f32 zero2;
        fi = 0;
        bi = 0;
        zero2 = lbl_803E3F44;
        for (i = 0; i < cfg->period; i++)
        {
            for (j = 0; j < cfg->period; j++)
            {
                f32 v = ((f32*)lbl_803DDAF4)[fi];
                if (v < zero2)
                {
                    f32 t = (v - cfg->minHeight) / negMin;
                    ((s8*)lbl_803DDAEC)[bi] = (s32)(lbl_803E3F54 * t + lbl_803E3F50);
                    ((s8*)lbl_803DDAEC)[bi + 1] = (s32)(lbl_803E3F5C * t + lbl_803E3F58);
                    ((s8*)lbl_803DDAEC)[bi + 2] = (s32)(lbl_803E3F64 * t + lbl_803E3F60);
                }
                else
                {
                    ((s8*)lbl_803DDAEC)[bi] = 255;
                    ((s8*)lbl_803DDAEC)[bi + 1] = 255;
                    ((s8*)lbl_803DDAEC)[bi + 2] = 255;
                }
                fi++;
                bi += 3;
            }
        }
    }

    lbl_803DDAF0 = mmAlloc(4 * cfg->gridN * cfg->gridN, 0xFFFFFF, 0);
    hi = 0;
    for (i = 0; i < cfg->gridN; i++)
    {
        for (j = 0; j < cfg->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[hi] = (s16)(i * 10);
            ((s16*)lbl_803DDAF0)[hi + 1] = (s16)(j * 10);
            hi += 2;
        }
    }
}
