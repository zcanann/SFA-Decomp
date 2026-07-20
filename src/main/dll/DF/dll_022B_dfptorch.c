/*
 * DragonRock Palace torch (DLL 0x22B; "DFP_Torch") - a lightable torch.
 * Tracks lit state and a flicker/burn timer, plays flame particle and
 * sfx effects while lit, and latches its lit-state gamebit.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/DF/dll_022B_dfptorch.h"
#include "main/dll/dll_0069_dll69func0.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/camera.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "main/voxmaps.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

/* DfpTorchState.mode: torch behaviour selected from placement->mode */
#define DFPTORCH_MODE_ALWAYS_LIT 0 /* permanently burning, ignited at init */
#define DFPTORCH_MODE_LIGHTABLE  1 /* player-toggled; burn timer + gamebit latch */

/* partfx ids: FLICKER emitted on the flicker-timer tick while the flame is
   visible; IGNITE spawned 100x on the unlit->lit transition (light-up burst) */
#define DFPTORCH_PARTFX_FLICKER 0x1f7
#define DFPTORCH_PARTFX_IGNITE  0x1a3

u8 gDfpTorchSequenceState;
const Dll69EffectParams gDfpTorchEffectParams = {0x3E7, 0x8C, 0x8D, 0x28};

int DFP_Torch_getExtraSize(void)
{
    return 0x10;
}
int DFP_Torch_getObjectTypeId(void)
{
    return 0x1;
}

void DFP_Torch_free(GameObject* obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

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
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        if (state->lit != 0)
        {
            state->visibleLatch = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = cam->x - (obj)->anim.localPosX;
            stk2.d[1] = cam->y - (obj)->anim.localPosY;
            stk2.d[2] = cam->z - (obj)->anim.localPosZ;
            {
                f32 sqZ = stk2.d[2] * stk2.d[2];
                f32 sqX = stk2.d[0] * stk2.d[0];
                f32 sqY = stk2.d[1] * stk2.d[1];
                dist = sqrtf(sqZ + (sqX + sqY));
            }
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

void DFP_Torch_hitDetect(void)
{
}

void DFP_Torch_update(GameObject* obj)
{
    DfpTorchState* state = obj->extra;
    Dll69Interface** res;
    int i;
    f32 buf[5];
    Dll69EffectParams prm;

    prm = gDfpTorchEffectParams;
    Sfx_PlayFromObject((u32)obj, SFXTRIG_mushdizzylp12);
    objUpdateOpacity(obj);
    switch (state->mode)
    {
    case DFPTORCH_MODE_ALWAYS_LIT:
        break;
    case DFPTORCH_MODE_LIGHTABLE:
        buf[4] = -2.0f;
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
            Sfx_PlayFromObject((u32)obj, SFXTRIG_cvdrip1c);
        }
        if (state->lit != state->prevLit)
        {
            if (state->lit != 0)
            {
                res = Resource_Acquire(0x69, 1);
                prm.param1 = state->colorIdx * 2 + 0x19d;
                prm.param2 = state->colorIdx * 2 + 0x19e;
                (*res)->spawn(obj, 1, buf, 0x10004, -1, &prm);
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
                Sfx_StopObjectChannel((int)obj, 0x40);
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

void DFP_Torch_init(GameObject* obj, DfpTorchPlacement* def)
{
    DfpTorchState* state = obj->extra;
    DfpTorchPlacement* place = def;
    Dll69Interface** res;
    struct
    {
        u8 pad[16];
        f32 val;
    } spawnArg;
    int motionRate;
    obj->anim.rotX = (s16)((place->rotPitch & 0x3f) << 10);
    motionRate = place->motionRate;
    if (motionRate > 0)
    {
        obj->anim.rootMotionScale = motionRate / 8192.0f;
    }
    else
    {
        obj->anim.rootMotionScale = 0.1f;
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
            (*res)->spawn(obj, 0, &spawnArg, 0x10004, -1, NULL);
        }
        break;
    }
    state->colorIdx = (u8)place->colorIdx;
    obj->objectFlags = obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void DFP_Torch_release(void)
{
}

void DFP_Torch_initialise(void)
{
}

ObjectDescriptor gDFP_TorchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_Torch_initialise, (ObjectDescriptorCallback)DFP_Torch_release, 0,
    (ObjectDescriptorCallback)DFP_Torch_init, (ObjectDescriptorCallback)DFP_Torch_update,
    (ObjectDescriptorCallback)DFP_Torch_hitDetect, (ObjectDescriptorCallback)DFP_Torch_render,
    (ObjectDescriptorCallback)DFP_Torch_free, (ObjectDescriptorCallback)DFP_Torch_getObjectTypeId,
    DFP_Torch_getExtraSize,
};
