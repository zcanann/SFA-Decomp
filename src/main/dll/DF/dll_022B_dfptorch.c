/*
 * DragonRock Palace torch (DLL 0x22B; "DFP_Torch") - a lightable torch.
 * Tracks lit state and a flicker/burn timer, plays flame particle and
 * sfx effects while lit, and latches its lit-state gamebit.
 */
#include "main/dll/dfptorchstate_struct.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/camera.h"
#include "main/audio/sfx.h"
extern void objRenderFn_8003b8f4(f32);
extern f32 sqrtf(f32 x);
extern int randomGetRange(int lo, int hi);
extern ModgfxInterface** gModgfxInterface;
extern f32 timeDelta;
extern f32 gDfpTorchMotionRateScale;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

void DFP_Torch_hitDetect(void)
{
}

void DFP_Torch_release(void)
{
}

void DFP_Torch_initialise(void)
{
}

int DFP_Torch_getExtraSize(void) { return 0x10; }
int DFP_Torch_getObjectTypeId(void) { return 0x1; }

void DFP_Torch_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void DFP_Torch_init(int obj, int def)
{
    DfpTorchState* state = ((GameObject*)obj)->extra;
    DfpTorchPlacement* place = (DfpTorchPlacement*)def;
    void* res;
    struct
    {
        u8 pad[16];
        f32 val;
    } spawnArg;
    int motionRate;
    ((GameObject*)obj)->anim.rotX = (s16)((place->rotPitch & 0x3f) << 10);
    motionRate = place->motionRate;
    if (motionRate > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = motionRate / gDfpTorchMotionRateScale;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63E8;
    }
    state->mode = place->mode;
    state->gameBit = place->gameBit;
    spawnArg.val = lbl_803E63E0;
    switch (state->mode)
    {
    case 0:
        state->lit = 1;
        res = Resource_Acquire(0x69, 1);
        if (place->colorIdx == 0)
        {
            (*(void (*)(int, int, void*, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, &spawnArg, 0x10004, -1, 0);
        }
        break;
    }
    state->colorIdx = (u8)place->colorIdx;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
}

#pragma opt_common_subs off
#pragma fp_contract off
void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{

    extern void voxmaps_worldToGrid(f32* in, s16* out);
    extern int voxmaps_traceLine(s16*, s16*, void*, int, int);
    extern f32 lbl_803E63C8;
    extern f32 gDfpTorchOcclusionCheckDistMin;
    extern f32 lbl_803E63D0;
    extern f32 lbl_803E63D4;
    extern f32 lbl_803E63D8;
    extern f32 lbl_803E63DC;
    DfpTorchState* state = ((GameObject*)obj)->extra;
    char* cam;
    f32 dist;
    f32 scale;
    struct
    {
        s32 out[2];
        s16 g2[4];
        s16 g1[4];
        f32 b[3];
        f32 a[3];
        f32 d[3];
        struct
        {
            u8 pad[12];
            f32 col[3];
        } fx;
    } stk2;

    if (visible == 0)
    {
        state->flickerTimer = 0;
        state->visibleLatch = 0;
    }
    else
    {
        objRenderFn_8003b8f4(lbl_803E63C8);
        if (state->lit != 0)
        {
            state->visibleLatch = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = *(f32*)(cam + 0xc) - ((GameObject*)obj)->anim.localPosX;
            stk2.d[1] = *(f32*)(cam + 0x10) - ((GameObject*)obj)->anim.localPosY;
            stk2.d[2] = *(f32*)(cam + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(stk2.d[2] * stk2.d[2] + (stk2.d[0] * stk2.d[0] + stk2.d[1] * stk2.d[1]));
            if (dist > gDfpTorchOcclusionCheckDistMin)
            {
                scale = lbl_803E63C8 / dist;
                stk2.d[0] *= scale;
                stk2.d[1] *= scale;
                stk2.d[2] *= scale;
                stk2.a[0] = lbl_803E63D0 * stk2.d[0];
                stk2.a[1] = lbl_803E63D0 * stk2.d[1];
                stk2.a[2] = lbl_803E63D0 * stk2.d[2];
                stk2.a[0] = stk2.a[0] + ((GameObject*)obj)->anim.localPosX;
                stk2.a[1] = stk2.a[1] + ((GameObject*)obj)->anim.localPosY;
                stk2.a[2] = stk2.a[2] + ((GameObject*)obj)->anim.localPosZ;
                stk2.b[0] = lbl_803E63D4 * stk2.d[0];
                stk2.b[1] = lbl_803E63D4 * stk2.d[1];
                stk2.b[2] = lbl_803E63D4 * stk2.d[2];
                stk2.b[0] = stk2.b[0] + *(f32*)(cam + 0xc);
                stk2.b[1] = stk2.b[1] + *(f32*)(cam + 0x10);
                stk2.b[2] = stk2.b[2] + *(f32*)(cam + 0x14);
                voxmaps_worldToGrid(stk2.a, stk2.g1);
                voxmaps_worldToGrid(stk2.b, stk2.g2);
                if (voxmaps_traceLine(stk2.g1, stk2.g2, stk2.out, 0, 0) == 0)
                {
                    state->visibleLatch = 0;
                    (*gExpgfxInterface)->freeSource((u32)obj);
                }
            }
            if (state->flickerTimer > 0)
            {
                state->flickerTimer -= (s16)timeDelta;
            }
            else
            {
                if (state->visibleLatch != 0)
                {
                    stk2.fx.col[0] = lbl_803E63D8;
                    stk2.fx.col[1] = lbl_803E63DC;
                    stk2.fx.col[2] = lbl_803E63D8;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &stk2.fx, 0x12, -1,
                                                     NULL);
                }
                state->flickerTimer = (s16)(randomGetRange(-10, 10) + 0x3c);
            }
        }
    }
}
#pragma fp_contract reset
#pragma opt_common_subs reset

void DFP_Torch_update(int obj)
{
    extern void Sfx_PlayFromObject(int, int);

    extern void objUpdateOpacity(int);
    extern u8 gDfpTorchSequenceState;
    extern int gDfpTorchEffectParams[];
    typedef struct
    {
        int m0;
        int m1;
        int m2;
        int m3;
    } TorchPrm;
    DfpTorchState* state = ((GameObject*)obj)->extra;
    void* res;
    int i;
    f32 buf[5];
    TorchPrm prm;

    prm = *(TorchPrm*)gDfpTorchEffectParams;
    Sfx_PlayFromObject(obj, 0x72);
    objUpdateOpacity(obj);
    switch (state->mode)
    {
    case 0:
        break;
    case 1:
        buf[4] = lbl_803E63E0;
        state->prevLit = state->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            state->lit = 1 - state->lit;
            if (state->lit != 0)
            {
                state->litTimer = 0x7d0;
            }
        }
        if (state->lit != 0)
        {
            if (state->litTimer != 0)
            {
                state->litTimer -= (s16)timeDelta;
                if (state->litTimer <= 0)
                {
                    state->litTimer = 0;
                    state->lit = 0;
                }
            }
        }
        if (state->lit != 0 && state->flickerTimer <= 0 && state->sfxPending != 0)
        {
            state->sfxPending = 0;
            Sfx_PlayFromObject(obj, 0x80);
        }
        if (state->lit != state->prevLit)
        {
            if (state->lit != 0)
            {
                res = Resource_Acquire(0x69, 1);
                prm.m1 = state->colorIdx * 2 + 0x19d;
                prm.m2 = state->colorIdx * 2 + 0x19e;
                (*(void (*)(int, int, f32*, int, int, void*))(*(int*)(*(int*)res + 4)))(obj, 1, buf, 0x10004, -1, &prm);
                Resource_Release(res);
                for (i = 0; i < 0x64; i++)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1a3, NULL, 0, -1,
                                                     NULL);
                }
                if (state->gameBit != -1)
                {
                    if (GameBit_Get(state->gameBit) == 0)
                    {
                        GameBit_Set(state->gameBit, 1);
                    }
                }
                if ((s8)gDfpTorchSequenceState == 0 && state->colorIdx == 0 && GameBit_Get(state->gameBit) != 0)
                {
                    gDfpTorchSequenceState = 1;
                }
                if ((s8)gDfpTorchSequenceState == 1 && state->colorIdx == 1 && GameBit_Get(state->gameBit) != 0)
                {
                    GameBit_Set(0x5e2, 1);
                    gDfpTorchSequenceState = 2;
                }
                state->sfxPending = 1;
                state->flickerTimer = 1;
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
                (*gModgfxInterface)->detachSource((void*)obj);
                (*gExpgfxInterface)->freeSource((u32)obj);
                if (state->gameBit != -1)
                {
                    if (GameBit_Get(state->gameBit) != 0)
                    {
                        GameBit_Set(state->gameBit, 0);
                    }
                }
                if ((s8)gDfpTorchSequenceState == 1 && state->colorIdx == 0)
                {
                    gDfpTorchSequenceState = 0;
                }
                if ((s8)gDfpTorchSequenceState == 2 && state->colorIdx == 1 && GameBit_Get(0x5e2) == 0)
                {
                    GameBit_Set(0x5e2, 0);
                    gDfpTorchSequenceState = 0;
                }
            }
        }
        break;
    }
}
