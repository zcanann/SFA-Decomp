/*
 * dll197 - the three-stage "cup" / spin-symbol contact puzzle object.
 *
 * objType 0 is the contact cup (Cup197State): it toggles active on a
 * priority hit, plays proximity sfx (channel 0x40), spawns 0x1a3 spark
 * particles and an 0x69 resource effect on activation, and drives a
 * three-stage progression latch (lbl_803DDBD0 0..3) keyed on its stage
 * (0..2) and gameBit. Stage 2 completion sets game bit 0x472.
 * objType 1 is the spin-symbol variant (Dll197State, getExtraSize 0x10),
 * set up by dll_197_init from placement bytes.
 *
 * render does a camera line-of-sight check (voxmaps_traceLine) before
 * emitting the 0x1f7 sparkle particle on a randomized cooldown.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/dll197state_struct.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/objhits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"
#include "main/voxmaps.h"
#include "main/dll/dll_0198_nwshlevcon.h"

typedef struct ResourceParamBlob
{
    int w[4];
} ResourceParamBlob;

STATIC_ASSERT(sizeof(ResourceParamBlob) == 0x10);

typedef struct Cup197State
{
    s32 gameBit;
    s16 sparkTimer;
    s16 activeTimer;
    s16 hitCooldown;
    u8 visibleToCamera;
    u8 mode;
    u8 active;
    u8 sparkArmed;
    u8 previousActive;
    u8 stage;
} Cup197State;

/* partfx ids (docblock: "spawns 0x1a3 spark particles" on activation;
 * render "emitting the 0x1f7 sparkle particle"). */
#define DLL197_PARTFX_SPARK   0x1a3
#define DLL197_PARTFX_SPARKLE 0x1f7

#define CUP_STAGE_COMPLETE_BIT 0x472

const ResourceParamBlob gDll197ResourceParamTemplate = {{0x3E7, 0x8C, 0x8D, 0x28}};
s8 lbl_803DDBD0; /* shared 0..3 progression latch */
__declspec(section ".sdata2") f32 lbl_803E5120 = 50.0f;
__declspec(section ".sdata2") f32 lbl_803E5124 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5128 = 32.0f;
__declspec(section ".sdata2") f32 lbl_803E512C = -20.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5130 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E5134 = 5.0f;
__declspec(section ".sdata2") f32 lbl_803E5138 = 90.0f;
__declspec(section ".sdata2") f32 lbl_803E513C = -2.0f;
__declspec(section ".sdata2") f32 lbl_803E5140 = 8192.0f;
__declspec(section ".sdata2") f32 lbl_803E5144 = 0.1f;

typedef struct Dll197Placement
{
    u8 pad0[0x18 - 0x0];
    u8 rotXParam;  /* 0x18: low 6 bits -> anim.rotX seed */
    u8 kind;       /* 0x19: object sub-type selector */
    s16 scale;     /* 0x1a: rootMotionScale numerator */
    s16 menuState; /* 0x1c: initial spin-symbol menu state */
    s16 unk1e;     /* 0x1e: latched into Dll197State word 0 */
} Dll197Placement;

int dll_197_getExtraSize(void)
{
    return 0x10;
}

int dll_197_getObjectTypeId(void)
{
    return 0x1;
}

void dll_197_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_197_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    struct
    {
        u8 pad[0xc];
        f32 pos[3];
    } particleParams;
    f32 dir[3];
    f32 objTrace[3];
    f32 cameraTrace[3];
    s16 startGrid[4];
    s16 endGrid[4];
    u8 traceOut[8];
    Cup197State* state = (obj)->extra;
    CameraViewSlot* camera;
    f32 dist;
    f32 scale;
    void* dirAlias = dir;

    if (visible == 0)
    {
        state->sparkTimer = 0;
        state->visibleToCamera = 0;
        return;
    }

    if (state->active == 0)
    {
        return;
    }

    state->visibleToCamera = 1;
    camera = Camera_GetCurrentViewSlot();
    dir[0] = camera->x - (obj)->anim.localPosX;
    dir[1] = camera->y - (obj)->anim.localPosY;
    dir[2] = camera->z - (obj)->anim.localPosZ;

    dist = sqrtf(dir[2] * dir[2] + (dir[0] * dir[0] + dir[1] * dir[1]));
    if (dist > lbl_803E5120)
    {
        scale = lbl_803E5124 / dist;
        dir[0] = dir[0] * scale;
        dir[1] = dir[1] * scale;
        dir[2] = dir[2] * scale;

        objTrace[0] = lbl_803E5128 * dir[0];
        objTrace[1] = lbl_803E5128 * dir[1];
        objTrace[2] = lbl_803E5128 * dir[2];
        objTrace[0] = objTrace[0] + (obj)->anim.localPosX;
        objTrace[1] = objTrace[1] + (obj)->anim.localPosY;
        objTrace[2] = objTrace[2] + (obj)->anim.localPosZ;
        cameraTrace[0] = lbl_803E512C * dir[0];
        cameraTrace[1] = lbl_803E512C * dir[1];
        cameraTrace[2] = lbl_803E512C * dir[2];
        cameraTrace[0] = cameraTrace[0] + camera->x;
        cameraTrace[1] = cameraTrace[1] + camera->y;
        cameraTrace[2] = cameraTrace[2] + camera->z;

        voxmaps_worldToGrid((void*)objTrace, startGrid);
        voxmaps_worldToGrid((void*)cameraTrace, endGrid);
        if (voxmaps_traceLine((VoxPos*)startGrid, (VoxPos*)endGrid, (VoxPos*)traceOut, NULL, 0) == 0)
        {
            state->visibleToCamera = 0;
            (*gExpgfxInterface)->freeSource((int)obj);
        }
    }

    if (state->sparkTimer > 0)
    {
        state->sparkTimer -= framesThisStep;
        return;
    }

    if (state->visibleToCamera != 0)
    {
        particleParams.pos[0] = lbl_803E5130;
        particleParams.pos[1] = lbl_803E5134;
        particleParams.pos[2] = lbl_803E5130;
        (*gPartfxInterface)->spawnObject((void*)obj, DLL197_PARTFX_SPARKLE, &particleParams, 0x12, -1, NULL);
    }

    state->sparkTimer = randomGetRange(-10, 10) + 0x3c;
}

void dll_197_hitDetect(void)
{
}

void dll_197_update(int obj)
{
    Cup197State* state = ((GameObject*)obj)->extra;
    ResourceParamBlob resourceParams;
    u8 callbackData[0x14];
    int player;
    f32 distance;
    void* resource;
    int effect;
    int stageEffectBase;

    resourceParams = gDll197ResourceParamTemplate;

    player = (int)Obj_GetPlayerObject();
    distance = Vec_distance((void*)(player + 0x18), &((GameObject*)obj)->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannelIntLegacy(obj, 0x40) != 0)
    {
        if (distance >= lbl_803E5138 && state->active != 0)
        {
            Sfx_StopObjectChannel(obj, 0x40);
        }
    }
    else if (distance < lbl_803E5138 && state->active != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
    }

    objUpdateOpacity((GameObject*)obj);

    if (state->hitCooldown > 0)
    {
        state->hitCooldown -= framesThisStep;
    }

    switch (state->mode)
    {
    case 1:
        break;
    case 0:
    default:
        return;
    }

    *(f32*)(callbackData + 0x10) = lbl_803E513C;
    state->previousActive = state->active;
    if (ObjHits_GetPriorityHit((GameObject*)(obj), 0, 0, 0) != 0 ||
        (state->hitCooldown != 0 && state->hitCooldown <= 0x14))
    {
        state->active = 1 - state->active;
        if (state->active != 0)
        {
            state->activeTimer = 1000;
        }
        if (state->hitCooldown != 0)
        {
            state->hitCooldown = 0;
            lbl_803DDBD0 = 3;
            state->activeTimer = 300;
            if (state->stage == 2)
            {
                mainSetBits(CUP_STAGE_COMPLETE_BIT, 1);
            }
        }
    }

    if (state->active != 0 && state->activeTimer != 0)
    {
        state->activeTimer -= framesThisStep;
        if (state->activeTimer <= 0)
        {
            state->activeTimer = 0;
            state->active = 0;
        }
    }

    if (state->active != 0 && state->sparkTimer <= 0 && state->sparkArmed != 0)
    {
        state->sparkArmed = 0;
        Sfx_PlayFromObject(obj, SFXTRIG_cvdrip1c);
    }

    if (state->active == state->previousActive)
    {
        return;
    }

    if (state->active != 0)
    {
        resource = Resource_Acquire(0x69, 1);
        stageEffectBase = state->stage * 2;
        resourceParams.w[1] = stageEffectBase + 0x19d;
        resourceParams.w[2] = stageEffectBase + 0x19e;
        (*(void (*)(int, int, void*, int, int, void*))(*(int*)(*(int*)resource + 4)))(obj, 1, callbackData, 0x10004, -1,
                                                                                      resourceParams.w);
        Resource_Release(resource);

        for (effect = 0; effect < 200; effect++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, DLL197_PARTFX_SPARK, NULL, 0, -1, NULL);
        }

        if (state->gameBit != -1 && mainGetBit(state->gameBit) == 0)
        {
            mainSetBits(state->gameBit, 1);
        }
        if (lbl_803DDBD0 == 0 && state->stage == 0 && mainGetBit(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 1;
        }
        if (lbl_803DDBD0 == 1 && state->stage == 1 && mainGetBit(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 2;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 2 && mainGetBit(state->gameBit) != 0)
        {
            mainSetBits(CUP_STAGE_COMPLETE_BIT, 1);
            lbl_803DDBD0 = 3;
        }
        state->sparkArmed = 1;
        state->sparkTimer = 1;
    }
    else
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        (*gModgfxInterface)->detachSource((void*)obj);
        (*gExpgfxInterface)->freeSource(obj);
        if (state->gameBit != -1 && mainGetBit(state->gameBit) != 0)
        {
            mainSetBits(state->gameBit, 0);
        }
        if (lbl_803DDBD0 == 1 && state->stage == 0)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 1)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 3 && state->stage == 2 && mainGetBit(0x474) == 0)
        {
            mainSetBits(CUP_STAGE_COMPLETE_BIT, 0);
            lbl_803DDBD0 = 0;
        }
    }
}

void dll_197_init(int obj, int dataArg)
{
    Dll197Placement* data = (Dll197Placement*)dataArg;
    u8* st;
    void* res;
    struct
    {
        u8 buf[16];
        f32 f;
    } stk;

    st = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(((s8)data->rotXParam & 0x3fu) << 10);
    if (data->scale > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)data->scale / lbl_803E5140;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5144;
    }
    *(u8*)(st + 0xb) = data->kind;
    ((Dll197State*)st)->unkC = 0;
    ((Dll197State*)st)->menuState = 0;
    *(int*)st = data->unk1e;
    stk.f = lbl_803E513C;
    switch (*(u8*)(st + 0xb))
    {
    case 0:
        ((Dll197State*)st)->unkC = 1;
        res = Resource_Acquire(0x69, 1);
        if (data->menuState == 0)
        {
            (*(void (**)(int, int, void*, int, int, int))(*(int*)res + 4))(obj, 0, stk.buf, 0x10004, -1, 0);
        }
        break;
    case 1:
        ((Dll197State*)st)->menuState = data->menuState;
        ((Dll197State*)st)->unkD = 0;
        ((Dll197State*)st)->scrollPos = ((Dll197State*)st)->menuState * 0x28 + 0x398;
        ((Dll197State*)st)->unkE = 0;
        break;
    }
    ((Dll197State*)st)->unk4 = 0;
}

void dll_197_release(void)
{
}

void dll_197_initialise(void)
{
}



ObjectDescriptor dll_197 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dll_197_initialise,
    dll_197_release,
    0,
    (ObjectDescriptorCallback)dll_197_init,
    (ObjectDescriptorCallback)dll_197_update,
    dll_197_hitDetect,
    (ObjectDescriptorCallback)dll_197_render,
    (ObjectDescriptorCallback)dll_197_free,
    (ObjectDescriptorCallback)dll_197_getObjectTypeId,
    dll_197_getExtraSize,
};

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gNWSH_levconObjDescriptor[14] = {(void*)0x00000000,           (void*)0x00000000,       (void*)0x00000000,
                                       (void*)0x00090000,           nwsh_levcon_initialise,  nwsh_levcon_release,
                                       (void*)0x00000000,           nwsh_levcon_init,        nwsh_levcon_update,
                                       nwsh_levcon_hitDetect,       nwsh_levcon_render,      nwsh_levcon_free,
                                       nwsh_levcon_getObjectTypeId, nwsh_levcon_getExtraSize};
