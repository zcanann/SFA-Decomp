/*
 * DLL 0xF7 (dll_F7) [8016984C-801713AC)
 *
 * The "dll_F7" object itself is a bouncing breakable prop: dll_F7_init acquires
 * its two model resources (0x5b/0x5a), dll_F7_update runs the hit/bounce logic
 * (hitsRemaining countdown, bounce offset/velocity damping, spawns a debris/
 * pickup object on break) and grants the placement's game bit on destruction.
 * The trailing GXWGFifo swipe* helpers are inlined display-list writers.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"
#include "main/dll/dll_005B_modgfxfunc03.h"
#include "main/dll/dll_00F7_dllf7_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_group.h"
#include "main/frame_timing.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/objprint_api.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00F7_dllf7.h"

#define DLLF7_OBJGROUP        0x3e
#define DLLF7_TARGET_OBJGROUP 0x4

#define DLLF7_OBJFLAG_HITDETECT_DISABLED 0x2000

/* child object id spawned via DllF7GasSetup buffer (gas cloud) */
#define DLLF7_CHILD_OBJ_GAS 0xb

struct DllF7Placement
{
    ObjPlacement base;
    s8 rotXByte;
    u8 alternateMode;
    s16 unk1A;
    s16 unk1C;
    s16 completeGameBit;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
};

/* Spawn-setup buffer seeded by dll_F7_update for the gas-cloud child (obj id
 * 0xb): position head plus the class-specific fields (see the target stb/sth). */
typedef struct DllF7GasSetup
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0c */
    f32 posZ; /* 0x10 */
    u8 pad14[0x1a - 0x14];
    u8 field1A;  /* 0x1a */
    u8 pad1B;    /* 0x1b */
    s16 field1C; /* 0x1c */
    u8 pad1E[0x24 - 0x1e];
    s16 field24; /* 0x24 */
    u8 pad26[0x2c - 0x26];
    s16 field2C; /* 0x2c */
} DllF7GasSetup;

typedef struct DllF7HitBlock
{
    StaffCollisionColorArgs params;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DllF7HitBlock;

const StaffCollisionColorArgs lbl_802C2260 = {8, 0xFF, 0xFF, 0x78};

/* dll_F7 (bouncing prop) object extra-state */
typedef struct DllF7State
{
    f32 bounceOffset;
    f32 bounceVelocity;
    u8 unk8;
    s8 broken;
    s8 hitsRemaining;
    s8 alternateMode;
} DllF7State;

STATIC_ASSERT(offsetof(DllF7Placement, base) == 0x0);
STATIC_ASSERT(offsetof(DllF7Placement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DllF7Placement, alternateMode) == 0x19);
STATIC_ASSERT(offsetof(DllF7Placement, completeGameBit) == 0x1E);
STATIC_ASSERT(sizeof(DllF7Placement) == 0x30);
STATIC_ASSERT(offsetof(DllF7State, bounceVelocity) == 0x4);
STATIC_ASSERT(offsetof(DllF7State, broken) == 0x9);
STATIC_ASSERT(offsetof(DllF7State, hitsRemaining) == 0xA);
STATIC_ASSERT(offsetof(DllF7State, alternateMode) == 0xB);
STATIC_ASSERT(sizeof(DllF7State) == 0xC);

StaffCollisionInterface** gDllF7Resource5A;
ModgfxFunc03Interface** gDllF7Resource5B;

int dll_F7_getExtraSize(void)
{
    return 0xc;
}
int dll_F7_getObjectTypeId(void)
{
    return 0x2;
}

void dll_F7_free(GameObject* obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(gDllF7Resource5B);
    Resource_Release(gDllF7Resource5A);
    gDllF7Resource5B = NULL;
    gDllF7Resource5A = NULL;
    ObjGroup_RemoveObject((int)obj, DLLF7_OBJGROUP);
}

void dll_F7_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DllF7State* state = obj->extra;
    if (state->broken == 0 && visible != 0)
    {
        f32 bounceOffset = state->bounceOffset;
        if (bounceOffset)
        {
            fn_8003B5E0(0xc8, 0, 0, bounceOffset);
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void dll_F7_hitDetect(void)
{
}

void dll_F7_update(GameObject* obj)
{
    DllF7State* state = obj->extra;
    DllF7HitBlock blk;
    f32 radius;
    u32 hitVolume;

    blk.params = lbl_802C2260;
    if (state->broken != 0)
    {
        DllF7Placement* placement = (DllF7Placement*)obj->anim.placementData;
        if (state->alternateMode == 0 && (*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId) != 0)
        {
            state->broken = 0;
            state->unk8 = 1;
            state->hitsRemaining = 2;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        }
        else
        {
            *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, &hitVolume, &blk.x, &blk.y, &blk.z) != 0)
    {
        if ((state->hitsRemaining -= hitVolume) > 0)
        {
            Sfx_PlayAtPositionFromObject((int)obj, blk.x, blk.y, blk.z, SFXTRIG_crtsmsh6);
            Obj_SetActiveModelIndex(obj, 2 - state->hitsRemaining);
            state->bounceOffset = 1.0f;
            state->bounceVelocity = 12.0f;
            blk.x += playerMapOffsetX;
            blk.z += playerMapOffsetZ;
            blk.scale = 1.0f;
            blk.rotZ = 0;
            blk.rotY = 0;
            blk.rotX = 0;
            (*gDllF7Resource5A)
                ->spawn(NULL, 1, (PartFxSpawnParams*)((int)&blk + 16), 1025, -1, &blk.params);
        }
    }
    if (state->hitsRemaining <= 0)
    {
        DllF7Placement* placement = (DllF7Placement*)obj->anim.placementData;
        if (state->alternateMode == 0)
        {
            (*gMapEventInterface)->addTime(placement->base.mapId, 1200.0f);
        }
        state->broken = 1;
        state->unk8 = 0;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_dsmk2_c);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if ((int)placement->completeGameBit != -1)
        {
            mainSetBits((int)placement->completeGameBit, 1);
        }
        if (state->alternateMode == 0 && (u8)Obj_IsLoadingLocked() != 0)
        {
            s16* alloc = (s16*)Obj_AllocObjectSetup(0x30, DLLF7_CHILD_OBJ_GAS);
            ((DllF7GasSetup*)alloc)->field1C = -1;
            ((DllF7GasSetup*)alloc)->posX = obj->anim.localPosX;
            ((DllF7GasSetup*)alloc)->posY = 10.0f + obj->anim.localPosY;
            ((DllF7GasSetup*)alloc)->posZ = obj->anim.localPosZ;
            ((DllF7GasSetup*)alloc)->field1A = 3;
            ((DllF7GasSetup*)alloc)->field2C = -1;
            ((DllF7GasSetup*)alloc)->field24 = -1;
            Obj_SetupObject((ObjPlacement*)alloc, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        }
        else
        {
            GameObject* near;
            radius = 50.0f;
            near = (GameObject*)ObjGroup_FindNearestObject(DLLF7_TARGET_OBJGROUP, obj, &radius);
            if (near != NULL)
            {
                near->anim.localPosX = near->anim.worldPosX = obj->anim.localPosX;
                near->anim.localPosY = near->anim.worldPosY = 10.0f + obj->anim.localPosY;
                near->anim.localPosZ = near->anim.worldPosZ = obj->anim.localPosZ;
                near->anim.rotX = obj->anim.rotX;
            }
        }
        (*gDllF7Resource5B)->spawn(obj, 1, NULL, 2, -1, NULL);
    }
    if (state->bounceOffset > 0.0f)
    {
        state->bounceOffset = timeDelta * state->bounceVelocity + state->bounceOffset;
        if (state->bounceOffset < 0.0f)
        {
            state->bounceOffset = 0.0f;
        }
        else if (state->bounceOffset > 120.0f)
        {
            state->bounceOffset = 120.0f - (state->bounceOffset - 120.0f);
            state->bounceVelocity = -state->bounceVelocity;
        }
    }
}

void dll_F7_init(GameObject* obj, DllF7Placement* placement)
{
    DllF7State* state = obj->extra;
    ObjGroup_AddObject((int)obj, DLLF7_OBJGROUP);
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags |= DLLF7_OBJFLAG_HITDETECT_DISABLED;
    gDllF7Resource5B = Resource_Acquire(0x5b, 1);
    gDllF7Resource5A = Resource_Acquire(0x5a, 1);
    {
        ObjModelState* modelState = obj->anim.modelState;
        if (modelState != NULL)
        {
            modelState->flags |= 0x810;
        }
    }
    *(u8*)&state->hitsRemaining = 2;
    *(u8*)&state->alternateMode = placement->alternateMode;
    if (state->alternateMode == 0)
    {
        int r = (*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId);
        if (r == 0)
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            hitState->flags &= ~1;
            *(u8*)&state->broken = 1;
            state->unk8 = 0;
        }
    }
}

void dll_F7_release(void)
{
}

void dll_F7_initialise(void)
{
}

ObjectDescriptor dll_F7 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_F7_initialise,
    (ObjectDescriptorCallback)dll_F7_release,
    0,
    (ObjectDescriptorCallback)dll_F7_init,
    (ObjectDescriptorCallback)dll_F7_update,
    (ObjectDescriptorCallback)dll_F7_hitDetect,
    (ObjectDescriptorCallback)dll_F7_render,
    (ObjectDescriptorCallback)dll_F7_free,
    (ObjectDescriptorCallback)dll_F7_getObjectTypeId,
    dll_F7_getExtraSize,
};

GenPropsWGPipe GXWGFifo : (0xCC008000);

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void swipeTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}
