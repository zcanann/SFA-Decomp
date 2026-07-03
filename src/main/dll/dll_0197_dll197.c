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
 *
 * NOTE: the dll_197 ObjectDescriptor (.data:0x803264E0, size 0x38) is not yet
 * claimed in splits.txt and is unimplemented here; data-section work pending.
 */
#include "main/dll/dll197state_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/objhits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"
extern int Obj_GetPlayerObject(void);
extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern f32 Vec_distance(f32* a, f32* b);
extern void objUpdateOpacity(int obj);
extern f32 sqrtf(f32 x);
extern void voxmaps_worldToGrid(f32* in, s16* out);
extern int voxmaps_traceLine(void* from, void* to, void* out, int p4, int p5);
extern ModgfxInterface** gModgfxInterface;
extern u8 framesThisStep;
extern int gDll197ResourceParamTemplate[];
extern s8 lbl_803DDBD0; /* shared 0..3 progression latch */
extern f32 lbl_803E5120;
extern f32 lbl_803E5124;
extern f32 lbl_803E5128;
extern f32 lbl_803E512C;
extern f32 lbl_803E5130;
extern f32 lbl_803E5134;
extern f32 lbl_803E5138;
extern f32 lbl_803E513C;
extern f32 lbl_803E5140;
extern f32 lbl_803E5144;

typedef struct ResourceParamBlob
{
    int w[4];
} ResourceParamBlob;

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

#define CUP_STAGE_COMPLETE_BIT 0x472

void dll_197_hitDetect(void)
{
}

void dll_197_update(int obj)
{
    Cup197State* state = ((GameObject*)obj)->extra;
    int resourceParams[4];
    u8 callbackData[0x14];
    int player;
    f32 distance;
    void* resource;
    int effect;
    int stageEffectBase;

    *(ResourceParamBlob*)resourceParams = *(ResourceParamBlob*)gDll197ResourceParamTemplate;

    player = Obj_GetPlayerObject();
    distance = Vec_distance((void*)(player + 0x18), &((GameObject*)obj)->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) != 0)
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

    objUpdateOpacity(obj);

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
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0 ||
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
                GameBit_Set(CUP_STAGE_COMPLETE_BIT, 1);
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
        resourceParams[1] = stageEffectBase + 0x19d;
        resourceParams[2] = stageEffectBase + 0x19e;
        (*(void (*)(int, int, void*, int, int, void*))(*(int*)(*(int*)resource + 4)))(
            obj, 1, callbackData, 0x10004, -1, resourceParams);
        Resource_Release(resource);

        for (effect = 0; effect < 200; effect++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x1a3, NULL, 0,
                                             -1, NULL);
        }

        if (state->gameBit != -1 && GameBit_Get(state->gameBit) == 0)
        {
            GameBit_Set(state->gameBit, 1);
        }
        if (lbl_803DDBD0 == 0 && state->stage == 0 && GameBit_Get(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 1;
        }
        if (lbl_803DDBD0 == 1 && state->stage == 1 && GameBit_Get(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 2;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 2 && GameBit_Get(state->gameBit) != 0)
        {
            GameBit_Set(CUP_STAGE_COMPLETE_BIT, 1);
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
        if (state->gameBit != -1 && GameBit_Get(state->gameBit) != 0)
        {
            GameBit_Set(state->gameBit, 0);
        }
        if (lbl_803DDBD0 == 1 && state->stage == 0)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 1)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 3 && state->stage == 2 && GameBit_Get(0x474) == 0)
        {
            GameBit_Set(CUP_STAGE_COMPLETE_BIT, 0);
            lbl_803DDBD0 = 0;
        }
    }
}

int dll_197_getExtraSize(void) { return 0x10; }
int dll_197_getObjectTypeId(void) { return 0x1; }

void dll_197_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
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
    Cup197State* state = ((GameObject*)obj)->extra;
    u8* camera;
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
    dir[0] = *(f32*)(camera + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dir[1] = *(f32*)(camera + 0x10) - ((GameObject*)obj)->anim.localPosY;
    dir[2] = *(f32*)(camera + 0x14) - ((GameObject*)obj)->anim.localPosZ;

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
        objTrace[0] = objTrace[0] + ((GameObject*)obj)->anim.localPosX;
        objTrace[1] = objTrace[1] + ((GameObject*)obj)->anim.localPosY;
        objTrace[2] = objTrace[2] + ((GameObject*)obj)->anim.localPosZ;
        cameraTrace[0] = lbl_803E512C * dir[0];
        cameraTrace[1] = lbl_803E512C * dir[1];
        cameraTrace[2] = lbl_803E512C * dir[2];
        cameraTrace[0] = cameraTrace[0] + *(f32*)(camera + 0xc);
        cameraTrace[1] = cameraTrace[1] + *(f32*)(camera + 0x10);
        cameraTrace[2] = cameraTrace[2] + *(f32*)(camera + 0x14);

        voxmaps_worldToGrid((void*)objTrace, startGrid);
        voxmaps_worldToGrid((void*)cameraTrace, endGrid);
        if (voxmaps_traceLine(startGrid, endGrid, traceOut, 0, 0) == 0)
        {
            state->visibleToCamera = 0;
            (*gExpgfxInterface)->freeSource(obj);
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
        (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &particleParams,
                                         0x12, -1, NULL);
    }

    state->sparkTimer = randomGetRange(-10, 10) + 0x3c;
}

void dll_197_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_197_init(int obj, int data)
{
    u8* st;
    void* res;
    struct
    {
        u8 buf[16];
        f32 f;
    } stk;

    st = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(((s8) * (u8*)(data + 0x18) & 0x3fu) << 10);
    if (*(s16*)(data + 0x1a) > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32) * (s16*)(data + 0x1a) / lbl_803E5140;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5144;
    }
    *(u8*)(st + 0xb) = *(u8*)(data + 0x19);
    ((Dll197State*)st)->unkC = 0;
    ((Dll197State*)st)->menuState = 0;
    *(int*)st = *(s16*)(data + 0x1e);
    stk.f = lbl_803E513C;
    switch (*(u8*)(st + 0xb))
    {
    case 0:
        ((Dll197State*)st)->unkC = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16*)(data + 0x1c) == 0)
        {
            (*(void (**)(int, int, void*, int, int, int))(*(int*)res + 4))(obj, 0, stk.buf, 0x10004, -1, 0);
        }
        break;
    case 1:
        ((Dll197State*)st)->menuState = *(s16*)(data + 0x1c);
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
