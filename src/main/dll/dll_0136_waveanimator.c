/*
 * waveanimator (DLL 0x136) - drives a procedurally rippling water/wave
 * surface for a map object. On init it folds the object's placement def
 * (origin/span/amplitude/period/grid) into a shared WaveAnimatorState and,
 * for the first instance only, builds three globally shared tables via
 * waveanimator_buildSharedTables: a per-cell height field, a per-cell RGB
 * color field shaded by height, and a per-grid phase table. hitDetect advances
 * every phase by framesThisStep/2 each
 * step (wrapping at the wave period); the tables are freed when the last
 * instance is destroyed.
 */
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/mm.h"
#include "main/object_descriptor.h"

typedef struct WaveAnimatorColor
{
    u8 red;
    u8 green;
    u8 blue;
} WaveAnimatorColor;

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(offsetof(WaveAnimatorState, modelMtxArg0) == 0x36);
STATIC_ASSERT(offsetof(WaveAnimatorState, modelMtxArg2) == 0x38);
STATIC_ASSERT(sizeof(WaveAnimatorColor) == 3);

#define WAVEANIMATOR_OBJGROUP 27

u8 gWaveAnimatorPhaseUpdateLatch;
f32* gWaveAnimatorHeightTable;
s16* gWaveAnimatorPhaseTable;
WaveAnimatorColor* gWaveAnimatorColorTable;
u8 gWaveAnimatorInstanceCount;


void waveanimator_buildSharedTables(int* cfgArg);

void waveanimator_modelMtxFn(GameObject* obj, int a, int b, int c)
{
    WaveAnimatorState* state = (WaveAnimatorState*)obj->extra;
    u32 v;
    v = (u32)state->flags | 4;
    state->flags = v;
    state->modelMtxArg0 = a;
    state->modelMtxArg1 = b;
    state->modelMtxArg2 = c;
}

void waveanimator_func0B(int* obj)
{
    WaveAnimatorState* state = (WaveAnimatorState*)((GameObject*)obj)->extra;
    state->flags |= 2;
}

void waveanimator_setScale(int* obj, f32 fval)
{
    WaveAnimatorState* state = (WaveAnimatorState*)((GameObject*)obj)->extra;
    state->flags |= 1;
    state->scaleB = fval;
}

void waveanimator_buildSharedTables(int* cfgArg)
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
    f32 waveY;
    f32 initHeight;
    WaveAnimatorState* cfg = (WaveAnimatorState*)cfgArg;

    gWaveAnimatorHeightTable = mmAlloc(sizeof(f32) * cfg->period * cfg->period, 0xFFFFFF, 0);
    gWaveAnimatorColorTable = mmAlloc(sizeof(WaveAnimatorColor) * cfg->period * cfg->period, 0xFFFFFF, 0);

    x = cfg->originX;
    stepX = (s32)((65536.0f * cfg->spanX) / cfg->period);
    y = cfg->originY;
    stepY = (s32)((65536.0f * cfg->spanY) / cfg->period);

    initHeight = 0.0f;
    cfg->maxHeight = initHeight;
    cfg->minHeight = initHeight;

    i = 0;
    heightIdx = 0;
    for (; i < cfg->period; i++)
    {
        f32 xv;
        j = 0;
        row = heightIdx;
        xv = 3.1415927f * x;
        for (; j < cfg->period; j++)
        {
            f32 s1 = mathSinf((3.1415927f * y) / 32768.0f);
            f32 s2;
            waveY = cfg->ampY * s1;
            s2 = mathSinf(xv / 32768.0f);
            *(f32*)((u8*)gWaveAnimatorHeightTable + row) = cfg->ampX * s2 + waveY;
            if (*(f32*)((u8*)gWaveAnimatorHeightTable + row) < cfg->minHeight)
            {
                cfg->minHeight = *(f32*)((u8*)gWaveAnimatorHeightTable + row);
            }
            if (*(f32*)((u8*)gWaveAnimatorHeightTable + row) > cfg->maxHeight)
            {
                cfg->maxHeight = *(f32*)((u8*)gWaveAnimatorHeightTable + row);
            }
            y += stepY;
            row += 4;
            heightIdx += 4;
        }
        x += stepX;
    }

    {
        f32 colorSplitZero;
        f32 t;
        f32 negMin = -cfg->minHeight;
        heightIdx = 0;
        x = heightIdx;
        i = heightIdx;
        colorSplitZero = 0.0f;
        for (; heightIdx < cfg->period; heightIdx++)
        {
            int src[1];
            int byte[1];
            for (j = 0, src[0] = x, byte[0] = i; j < cfg->period; src[0] += 4, byte[0] += 3, x += 4, i += 3, j++)
            {
                f32 v = *(f32*)((u8*)gWaveAnimatorHeightTable + src[0]);
                if (v < colorSplitZero)
                {
                    t = (v - cfg->minHeight) / negMin;
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0]) = 65.0f * t + 190.0f;
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0] + 1) = 165.0f * t + 90.0f;
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0] + 2) = 235.0f * t + 20.0f;
                }
                else
                {
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0]) = 255;
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0] + 1) = 255;
                    *(u8*)((u8*)gWaveAnimatorColorTable + byte[0] + 2) = 255;
                }
            }
        }
    }

    gWaveAnimatorPhaseTable = mmAlloc(2 * sizeof(s16) * cfg->gridN * cfg->gridN, 0xFFFFFF, 0);
    phaseIdx = 0;
    for (i = 0; i < cfg->gridN; i++)
    {
        for (j = 0; j < cfg->gridN; j++)
        {
            gWaveAnimatorPhaseTable[phaseIdx] = (s16)(i * 10);
            gWaveAnimatorPhaseTable[phaseIdx + 1] = (s16)(j * 10);
            phaseIdx += 2;
        }
    }
}


int waveanimator_getExtraSize(void)
{
    return sizeof(WaveAnimatorState);
}
int waveanimator_getObjectTypeId(void)
{
    return 0x0;
}

void waveanimator_free(int* obj)
{
    if (--gWaveAnimatorInstanceCount == 0)
    {
        if (gWaveAnimatorHeightTable != NULL)
            mm_free(gWaveAnimatorHeightTable);
        if (gWaveAnimatorPhaseTable != NULL)
            mm_free(gWaveAnimatorPhaseTable);
        if (gWaveAnimatorColorTable != NULL)
            mm_free(gWaveAnimatorColorTable);
    }
    ObjGroup_RemoveObject((int)obj, WAVEANIMATOR_OBJGROUP);
}

void waveanimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (1.0f));
}

void waveanimator_hitDetect(int* obj)
{
    int i;
    int j;
    int phaseIdx;
    WaveAnimatorState* state;
    if (gWaveAnimatorPhaseUpdateLatch != 0)
    {
        return;
    }
    state = (WaveAnimatorState*)((GameObject*)obj)->extra;
    phaseIdx = 0;
    for (i = 0; i < state->gridN; i++)
    {
        for (j = 0; j < state->gridN; j++)
        {
            gWaveAnimatorPhaseTable[phaseIdx] += framesThisStep >> 1;
            while (gWaveAnimatorPhaseTable[phaseIdx] >= state->period)
            {
                gWaveAnimatorPhaseTable[phaseIdx] -= state->period;
            }
            gWaveAnimatorPhaseTable[phaseIdx + 1] += framesThisStep >> 1;
            while (gWaveAnimatorPhaseTable[phaseIdx + 1] >= state->period)
            {
                gWaveAnimatorPhaseTable[phaseIdx + 1] -= state->period;
            }
            phaseIdx += 2;
        }
    }
    gWaveAnimatorPhaseUpdateLatch = 1;
}

void waveanimator_update(void)
{
}

void waveanimator_init(int* obj, int* desc)
{
    WaveAnimatorState* state = (WaveAnimatorState*)((GameObject*)obj)->extra;
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
    scale = (1.0f);
    state->scaleA = scale;
    state->scaleB = scale;
    if (gWaveAnimatorInstanceCount == 0)
    {
        waveanimator_buildSharedTables((int*)state);
    }
    ObjGroup_AddObject((int)obj, WAVEANIMATOR_OBJGROUP);
    gWaveAnimatorInstanceCount++;
}

void waveanimator_release(void)
{
}

void waveanimator_initialise(void)
{
}

ObjectDescriptor14 gWaveAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)waveanimator_initialise,
    (ObjectDescriptorCallback)waveanimator_release,
    0,
    (ObjectDescriptorCallback)waveanimator_init,
    (ObjectDescriptorCallback)waveanimator_update,
    (ObjectDescriptorCallback)waveanimator_hitDetect,
    (ObjectDescriptorCallback)waveanimator_render,
    (ObjectDescriptorCallback)waveanimator_free,
    (ObjectDescriptorCallback)waveanimator_getObjectTypeId,
    (ObjectDescriptorCallback)waveanimator_getExtraSize,
    (ObjectDescriptorCallback)waveanimator_setScale,
    (ObjectDescriptorCallback)waveanimator_func0B,
    (ObjectDescriptorCallback)waveanimator_modelMtxFn,
    0,
};
