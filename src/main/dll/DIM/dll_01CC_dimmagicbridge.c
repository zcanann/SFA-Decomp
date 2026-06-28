/*
 * dimmagicbridge (DLL 0x1CC) - the flame bridge across a lava gap.
 *
 * The bridge mesh is a strip of segments whose vertices are displaced by a
 * travelling sine wave (dimmagicbridge_updateVertexWave) while two material
 * channels scroll (dimmagicbridge_scrollTextureChannels). When ignited
 * (gamebit 0x1E9, or once the player's emission controller lingers over
 * gamebit 0x1EF) it fires the death VFX (fn_80065574) and latches gamebit
 * 0x1E8; the flame sequence (dimmagicbridge_flameSeqFn) lights successive
 * segments and ramps their glow toward full.
 *
 * The per-object extra block is DimMagicBridgeState (getExtraSize == 0x68);
 * the flame-sequence fields are overlaid via DimmagicbridgeFlameSeqFnState.
 */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIM2flameburst.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DIM/dll_01CC_dimmagicbridge.h"
#include "dolphin/os/OSCache.h"

typedef struct DimmagicbridgeFlameSeqFnState
{
    u8 pad0[0x51 - 0x0];
    u8 alpha;
    u8 pad52[0x60 - 0x52];
    u16 wavePhaseA;
    u8 pad62[0x64 - 0x62];
    s16 seqTimer;
    u8 pad66[0x68 - 0x66];
} DimmagicbridgeFlameSeqFnState;

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

#define DIMMAGICBRIDGE_GAMEBIT_IGNITED   0x1e9
#define DIMMAGICBRIDGE_GAMEBIT_TRIGGER   0x1ef
#define DIMMAGICBRIDGE_GAMEBIT_LATCH     0x1e8

extern int Obj_GetActiveModel(int obj);
extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern void fn_80065574(int matchVal, int obj, int flag);
extern f32 lbl_803E4A18;

extern int EmissionController_IsLingering(void* player);
extern u8 framesThisStep;
extern f32 lbl_803E4A00;
extern f32 lbl_803E4A04;
extern f32 lbl_803E4A08;
extern f32 lbl_803E4A0C;
extern int ObjModel_GetBaseVertexCoords(int mdl, int idx);
extern float mathSinf(float x);


void dimmagicbridge_free(void)
{
}

void dimmagicbridge_hitDetect(void)
{
}

void dimmagicbridge_release(void)
{
}

void dimmagicbridge_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void dimmagicbridge_init(u8* obj, u8* params)
{
    DimMagicBridgeState * sub;
    int i;
    s32 minY;
    int model;
    int modelData;
    f32* p;
    int j;
    int stable;
    f32 a, b;
    int v;
    s16 hh;

    ((GameObject*)obj)->anim.rotX = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->animEventCallback = dimmagicbridge_flameSeqFn;
    sub = ((GameObject*)obj)->extra;
    minY = 0;
    model = Obj_GetActiveModel((int)obj);
    modelData = *(int*)model;

    i = 0;
    while (i < *(u16*)(modelData + 0xe4))
    {
        v = ObjModel_GetCurrentVertexCoords(model, i);
        hh = *(s16*)(v + 4);
        if (hh < minY)
        {
            minY = hh;
        }
        i++;
    }

    stable = 0;
    while (stable == 0)
    {
        stable = 1;
        j = 0;
        p = (f32*)sub;
        while (j < sub->segmentCount - 1)
        {
            a = p[1];
            b = p[2];
            if (a < b)
            {
                p[1] = b;
                p[2] = (f32)(s32)
                a;
                stable = 0;
            }
            p++;
            j++;
        }
    }

    sub->segmentCount = 0xa;
    sub->minVertexY = minY;

    if (GameBit_Get(DIMMAGICBRIDGE_GAMEBIT_IGNITED) != 0)
    {
        sub->ignited = 1;
    }
    if (sub->ignited != 0)
    {
        for (i = 0; i < sub->segmentCount; i++)
        {
            sub->segmentGlow[i] = 0xff;
            sub->segmentLit[i] = 1;
            fn_80065574(0x11, 0, 0);
        }
    }
}

int dimmagicbridge_getExtraSize(void) { return 0x68; }
int dimmagicbridge_getObjectTypeId(void) { return 0x0; }

void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4A18);
}

#pragma peephole on
void dimmagicbridge_update(int obj)
{
    DimMagicBridgeState * sub;
    void* player;
    player = Obj_GetPlayerObject();
    sub = ((GameObject*)obj)->extra;
    dimmagicbridge_scrollTextureChannels(obj, (u8*)sub);
    dimmagicbridge_updateVertexWave(obj, (u8*)sub);
    if (sub->ignited == 0)
    {
        if (GameBit_Get(DIMMAGICBRIDGE_GAMEBIT_TRIGGER) != 0)
        {
            if (EmissionController_IsLingering(player) != 0)
            {
                GameBit_Set(DIMMAGICBRIDGE_GAMEBIT_LATCH, 1);
            }
        }
    }
    else
    {
        fn_80065574(0x11, 0, 0);
    }
}

#pragma peephole off
#pragma dont_inline on
void dimmagicbridge_scrollTextureChannels(int arg1, u8* obj)
{
    DimMagicBridgeState* sub = (DimMagicBridgeState*)obj;
    ObjTextureRuntimeSlot* tex;
    s32 v;

    tex = objFindTexture((void*)arg1, 0, 0);
    tex->offsetT += 0x14;
    if (tex->offsetT > 10000)
    {
        tex->offsetT -= 10000;
    }
    tex->offsetS += 10;
    if (tex->offsetS > 10000)
    {
        tex->offsetS -= 10000;
    }
    tex = objFindTexture((void*)arg1, 1, 0);
    tex->offsetT += 0x1e;
    if (tex->offsetT > 10000)
    {
        tex->offsetT -= 10000;
    }
    v = (s32)sub->wavePhase + framesThisStep * 0x100;
    if (v > 0xffff) v = v - 0xffff;
    sub->wavePhase = v;
    v = (s32)sub->wavePhaseB + framesThisStep * 0x80;
    if (v > 0xffff) v = v - 0xffff;
    sub->wavePhaseB = v;
}
#pragma dont_inline reset

#pragma peephole off
int dimmagicbridge_flameSeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int j;
    int i;
    u8* sub = ((GameObject*)obj)->extra;
    DimMagicBridgeState* state = (DimMagicBridgeState*)sub;
    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair &= ~0x40;
    dimmagicbridge_scrollTextureChannels(obj, sub);
    if (animUpdate->triggerCommand == 1)
    {
        animUpdate->triggerCommand = 0;
        state->ignited = 1;
    }
    if (state->ignited != 0)
    {
        ((DimmagicbridgeFlameSeqFnState*)sub)->seqTimer -= framesThisStep;
        if (((DimmagicbridgeFlameSeqFnState*)sub)->seqTimer <= 0)
        {
            ((DimmagicbridgeFlameSeqFnState*)sub)->seqTimer = 0x10;
            for (j = 1; sub[0x40 + j] != 0 && j < state->segmentCount; j++)
            {
            }
            sub[0x40 + j] = 1;
        }
        for (i = 1; i < state->segmentCount; i++)
        {
            if (sub[0x40 + i] != 0)
            {
                int sv = sub[0x50 + i];
                int v = sv + framesThisStep;
                if (v > 0xff) v = 0xff;
                sub[0x50 + i] = v;
            }
        }
    }
    dimmagicbridge_updateVertexWave(obj, sub);
    return 0;
}

volatile FbWGPipe GXWGFifo : (0xCC008000);

void dimmagicbridge_updateVertexWave(int obj, u8* sub)
{
    int i;
    int cnt;
    int mdl;
    int model;
    f32 amp;
    DimMagicBridgeState* state = (DimMagicBridgeState*)sub;
    model = Obj_GetActiveModel(obj);
    mdl = *(int*)model;
    i = 0;
    amp = lbl_803E4A00;
    for (; cnt = *(u16*)((char*)mdl + 0xe4), i < cnt; i++)
    {
        s16* vc = (s16*)ObjModel_GetCurrentVertexCoords(model, i);
        s16* vb = (s16*)ObjModel_GetBaseVertexCoords(mdl, i);
        int u = (u16)(int)(amp * ((f32)(int)vc[2] / state->minVertexY));
        u = u + state->wavePhase;
        if (*vb > 0)
        {
            *vc = lbl_803E4A04 * mathSinf((lbl_803E4A08 * (f32)(int)u) / lbl_803E4A0C
            )
            +(f32)(int) * vb;
        }
        else
        {
            *vc = -(lbl_803E4A04 * mathSinf((lbl_803E4A08 * (f32)(int)u) / lbl_803E4A0C) - (f32)(int) * vb
            )
            ;
        }
    }
    DCStoreRange((void*)ObjModel_GetCurrentVertexCoords(model, 0), cnt * 6);
    ((GameObject*)obj)->anim.alpha = state->segmentGlow[1];
}
