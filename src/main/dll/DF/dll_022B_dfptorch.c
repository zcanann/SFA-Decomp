/*
 * DragonRock Palace torch (DLL 0x22B; "DFP_Torch") - a lightable torch.
 * Tracks lit state and a flicker/burn timer, plays flame particle and
 * sfx effects while lit, and latches its lit-state gamebit.
 */
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/DF/dll_022B_dfptorch.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/camera.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gameplay_runtime.h"
#include "main/shader_api.h"
#include "main/voxmaps.h"

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

#define DFPTORCH_OBJFLAG_HITDETECT_DISABLED 0x2000

/* DfpTorchState.mode: torch behaviour selected from placement->mode */
#define DFPTORCH_MODE_ALWAYS_LIT 0 /* permanently burning, ignited at init */
#define DFPTORCH_MODE_LIGHTABLE  1 /* player-toggled; burn timer + gamebit latch */

/* partfx ids: FLICKER emitted on the flicker-timer tick while the flame is
   visible; IGNITE spawned 100x on the unlit->lit transition (light-up burst) */
#define DFPTORCH_PARTFX_FLICKER 0x1f7
#define DFPTORCH_PARTFX_IGNITE  0x1a3

extern u8 gDfpTorchSequenceState;
extern int gDfpTorchEffectParams[];

int DFP_Torch_getExtraSize(void)
{
    return 0x10;
}
int DFP_Torch_getObjectTypeId(void)
{
    return 0x1;
}

void DFP_Torch_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

#pragma opt_common_subs off
#pragma fp_contract off
void DFP_Torch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{

    DfpTorchState* state = (obj)->extra;
    CameraViewSlot* cam;
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
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
        if (state->lit != 0)
        {
            state->visibleLatch = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = cam->x - (obj)->anim.localPosX;
            stk2.d[1] = cam->y - (obj)->anim.localPosY;
            stk2.d[2] = cam->z - (obj)->anim.localPosZ;
            dist = sqrtf(stk2.d[2] * stk2.d[2] + (stk2.d[0] * stk2.d[0] + stk2.d[1] * stk2.d[1]));
            if (dist > 50.0f)
            {
                scale = 1.0f / dist;
                stk2.d[0] *= scale;
                stk2.d[1] *= scale;
                stk2.d[2] *= scale;
                stk2.a[0] = 32.0f * stk2.d[0];
                stk2.a[1] = 32.0f * stk2.d[1];
                stk2.a[2] = 32.0f * stk2.d[2];
                stk2.a[0] = stk2.a[0] + (obj)->anim.localPosX;
                stk2.a[1] = stk2.a[1] + (obj)->anim.localPosY;
                stk2.a[2] = stk2.a[2] + (obj)->anim.localPosZ;
                stk2.b[0] = -20.0f * stk2.d[0];
                stk2.b[1] = -20.0f * stk2.d[1];
                stk2.b[2] = -20.0f * stk2.d[2];
                stk2.b[0] = stk2.b[0] + cam->x;
                stk2.b[1] = stk2.b[1] + cam->y;
                stk2.b[2] = stk2.b[2] + cam->z;
                voxmaps_worldToGrid(stk2.a, stk2.g1);
                voxmaps_worldToGrid(stk2.b, stk2.g2);
                if (voxmaps_traceLine((VoxPos*)stk2.g1, (VoxPos*)stk2.g2, (VoxPos*)stk2.out, NULL, 0) == 0)
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
                    stk2.fx.col[0] = 0.0f;
                    stk2.fx.col[1] = 5.0f;
                    stk2.fx.col[2] = 0.0f;
                    (*gPartfxInterface)->spawnObject((void*)obj, DFPTORCH_PARTFX_FLICKER, &stk2.fx, 0x12, -1, NULL);
                }
                state->flickerTimer = (s16)(randomGetRange(-10, 10) + 0x3c);
            }
        }
    }
}
#pragma fp_contract reset
#pragma opt_common_subs reset

void DFP_Torch_hitDetect(void)
{
}

void DFP_Torch_update(int obj)
{
    extern void Sfx_PlayFromObject(int, int);

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
    Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
    objUpdateOpacity((GameObject*)obj);
    switch (state->mode)
    {
    case DFPTORCH_MODE_ALWAYS_LIT:
        break;
    case DFPTORCH_MODE_LIGHTABLE:
        buf[4] = -2.0f;
        state->prevLit = state->lit;
        if (ObjHits_GetPriorityHit((GameObject*)(obj), 0, 0, 0) != 0)
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
            Sfx_PlayFromObject(obj, SFXTRIG_cvdrip1c);
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
                    (*gPartfxInterface)->spawnObject((void*)obj, DFPTORCH_PARTFX_IGNITE, NULL, 0, -1, NULL);
                }
                if (state->gameBit != -1)
                {
                    if (mainGetBit(state->gameBit) == 0)
                    {
                        mainSetBits(state->gameBit, 1);
                    }
                }
                if ((s8)gDfpTorchSequenceState == 0 && state->colorIdx == 0 && mainGetBit(state->gameBit) != 0)
                {
                    gDfpTorchSequenceState = 1;
                }
                if ((s8)gDfpTorchSequenceState == 1 && state->colorIdx == 1 && mainGetBit(state->gameBit) != 0)
                {
                    mainSetBits(0x5e2, 1);
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
                    if (mainGetBit(state->gameBit) != 0)
                    {
                        mainSetBits(state->gameBit, 0);
                    }
                }
                if ((s8)gDfpTorchSequenceState == 1 && state->colorIdx == 0)
                {
                    gDfpTorchSequenceState = 0;
                }
                if ((s8)gDfpTorchSequenceState == 2 && state->colorIdx == 1 && mainGetBit(0x5e2) == 0)
                {
                    mainSetBits(0x5e2, 0);
                    gDfpTorchSequenceState = 0;
                }
            }
        }
        break;
    }
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
        ((GameObject*)obj)->anim.rootMotionScale = motionRate / 8192.0f;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = 0.1f;
    }
    state->mode = place->mode;
    state->gameBit = place->gameBit;
    spawnArg.val = -2.0f;
    switch (state->mode)
    {
    case DFPTORCH_MODE_ALWAYS_LIT:
        state->lit = 1;
        res = Resource_Acquire(0x69, 1);
        if (place->colorIdx == 0)
        {
            (*(void (*)(int, int, void*, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, &spawnArg, 0x10004, -1, 0);
        }
        break;
    }
    state->colorIdx = (u8)place->colorIdx;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | DFPTORCH_OBJFLAG_HITDETECT_DISABLED;
}

void DFP_Torch_release(void)
{
}

void DFP_Torch_initialise(void)
{
}
