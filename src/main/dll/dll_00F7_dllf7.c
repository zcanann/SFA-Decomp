/*
 * DLL 0xF7 (dll_F7) [8016984C-801713AC)
 *
 * The "dll_F7" object itself is a bouncing breakable prop: dll_F7_init acquires
 * its two model resources (0x5b/0x5a), dll_F7_update runs the hit/bounce logic
 * (hitsRemaining countdown, bounce offset/velocity damping, spawns a debris/
 * pickup object on break) and grants the placement's game bit on destruction.
 * The trailing GXWGFifo swipe* helpers are inlined display-list writers.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/genpropswgpipe_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/objprint.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"

#define DLLF7_OBJGROUP        0x3e
#define DLLF7_TARGET_OBJGROUP 0x4

#define DLLF7_OBJFLAG_HITDETECT_DISABLED 0x2000

/* child object id spawned via DllF7GasSetup buffer (gas cloud) */
#define DLLF7_CHILD_OBJ_GAS 0xb

extern ModgfxInterface** gModgfxInterface;

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern f32 timeDelta;

typedef struct DllF7Placement
{
    u8 pad0[0x14 - 0x0];
    s32 mapEventId;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 completeGameBit;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} DllF7Placement;

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

typedef struct DllF7Vec
{
    u8 b[16];
} DllF7Vec;

typedef struct DllF7HitBlock
{
    DllF7Vec params;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DllF7HitBlock;

extern DllF7Vec lbl_802C2260;

/* dll_F7 (bouncing prop) object extra-state */
typedef struct DllF7State
{
    f32 bounceOffset;
    f32 bounceVelocity;
    u8 byte8;
    s8 byte9;
    s8 hitsRemaining;
    s8 byteB;
} DllF7State;

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);

extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern const f32 lbl_803E3400;
extern const f32 lbl_803E3404;
extern f32 lbl_803E3408;
extern f32 lbl_803E340C;
extern f32 lbl_803E3410;
extern f32 lbl_803E3414;
extern f32 lbl_803E3418;
extern void fn_8003B5E0(int a, int b, int c, u8 d);
extern void Sfx_PlayAtPositionFromObject(int* obj, f32 x, f32 y, f32 z, int sfx);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern void* gDllF7Resource5B;
extern void* gDllF7Resource5A;

int dll_F7_getExtraSize(void)
{
    return 0xc;
}
int dll_F7_getObjectTypeId(void)
{
    return 0x2;
}

void dll_F7_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(gDllF7Resource5B);
    Resource_Release(gDllF7Resource5A);
    gDllF7Resource5B = NULL;
    gDllF7Resource5A = NULL;
    ObjGroup_RemoveObject(obj, DLLF7_OBJGROUP);
}

void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DllF7State* state = ((GameObject*)obj)->extra;
    if (state->byte9 == 0 && visible != 0)
    {
        f32 v = state->bounceOffset;
        if (v != lbl_803E3400)
        {
            fn_8003B5E0(0xc8, 0, 0, v);
        }
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3404);
    }
}

void dll_F7_hitDetect(void)
{
}

void dll_F7_update(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfx);
    extern u32 ObjGroup_FindNearestObject();
    DllF7State* state = ((GameObject*)obj)->extra;
    DllF7HitBlock blk;
    f32 radius;
    u32 hitVolume;

    blk.params = lbl_802C2260;
    if (state->byte9 != 0)
    {
        int* params = *(int**)&((GameObject*)obj)->anim.placementData;
        if (state->byteB == 0 && (*gMapEventInterface)->shouldNotSaveTime(((DllF7Placement*)params)->mapEventId) != 0)
        {
            state->byte9 = 0;
            state->byte8 = 1;
            state->hitsRemaining = 2;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition((int)obj, 0, 0, &hitVolume, &blk.x, &blk.y, &blk.z) != 0)
    {
        if ((state->hitsRemaining -= hitVolume) > 0)
        {
            Sfx_PlayAtPositionFromObject(obj, blk.x, blk.y, blk.z, SFXTRIG_crtsmsh6);
            Obj_SetActiveModelIndex(obj, 2 - state->hitsRemaining);
            state->bounceOffset = lbl_803E3404;
            state->bounceVelocity = lbl_803E3408;
            blk.x += playerMapOffsetX;
            blk.z += playerMapOffsetZ;
            blk.scale = lbl_803E3404;
            blk.rotZ = 0;
            blk.rotY = 0;
            blk.rotX = 0;
            ((void (*)(int, int, s16*, int, int, DllF7Vec*))((int*)*(int**)gDllF7Resource5A)[1])(
                0, 1, (s16*)((int)&blk + 16), 1025, -1, &blk.params);
        }
    }
    if (state->hitsRemaining <= 0)
    {
        int* params = *(int**)&((GameObject*)obj)->anim.placementData;
        if (state->byteB == 0)
        {
            (*gMapEventInterface)->addTime(((DllF7Placement*)params)->mapEventId, lbl_803E340C);
        }
        state->byte9 = 1;
        state->byte8 = 0;
        Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if ((int)((DllF7Placement*)params)->completeGameBit != -1)
        {
            mainSetBits((int)((DllF7Placement*)params)->completeGameBit, 1);
        }
        if (state->byteB == 0 && (u8)Obj_IsLoadingLocked() != 0)
        {
            s16* alloc = Obj_AllocObjectSetup(0x30, DLLF7_CHILD_OBJ_GAS);
            ((DllF7GasSetup*)alloc)->field1C = -1;
            ((DllF7GasSetup*)alloc)->posX = ((GameObject*)obj)->anim.localPosX;
            ((DllF7GasSetup*)alloc)->posY = lbl_803E3410 + ((GameObject*)obj)->anim.localPosY;
            ((DllF7GasSetup*)alloc)->posZ = ((GameObject*)obj)->anim.localPosZ;
            ((DllF7GasSetup*)alloc)->field1A = 3;
            ((DllF7GasSetup*)alloc)->field2C = -1;
            ((DllF7GasSetup*)alloc)->field24 = -1;
            Obj_SetupObject(alloc, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        }
        else
        {
            int* near;
            radius = lbl_803E3414;
            near = (int*)ObjGroup_FindNearestObject(DLLF7_TARGET_OBJGROUP, obj, &radius);
            if (near != NULL)
            {
                ((GameObject*)near)->anim.localPosX = ((GameObject*)near)->anim.worldPosX =
                    ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)near)->anim.localPosY = ((GameObject*)near)->anim.worldPosY =
                    lbl_803E3410 + ((GameObject*)obj)->anim.localPosY;
                ((GameObject*)near)->anim.localPosZ = ((GameObject*)near)->anim.worldPosZ =
                    ((GameObject*)obj)->anim.localPosZ;
                *(s16*)near = *(s16*)obj;
            }
        }
        ((void (*)(int*, int, int, int, int, int))((int*)*(int**)gDllF7Resource5B)[1])(obj, 1, 0, 2, -1, 0);
    }
    if (state->bounceOffset > lbl_803E3400)
    {
        state->bounceOffset = timeDelta * state->bounceVelocity + state->bounceOffset;
        if (state->bounceOffset < lbl_803E3400)
        {
            state->bounceOffset = lbl_803E3400;
        }
        else if (state->bounceOffset > lbl_803E3418)
        {
            state->bounceOffset = lbl_803E3418 - (state->bounceOffset - lbl_803E3418);
            state->bounceVelocity = -state->bounceVelocity;
        }
    }
}

void dll_F7_init(int* obj, int* params)
{
    int* state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject((int)obj, DLLF7_OBJGROUP);
    *(s16*)obj = (s16)((s8) * (s8*)((char*)params + 0x18) << 8);
    ((GameObject*)obj)->objectFlags |= DLLF7_OBJFLAG_HITDETECT_DISABLED;
    gDllF7Resource5B = Resource_Acquire(0x5b, 1);
    gDllF7Resource5A = Resource_Acquire(0x5a, 1);
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->flags |= 0x810;
        }
    }
    *(u8*)&((DllF7State*)state)->hitsRemaining = 2;
    *(u8*)&((DllF7State*)state)->byteB = *(u8*)((char*)params + 0x19);
    if (((DllF7State*)state)->byteB == 0)
    {
        int r = (*gMapEventInterface)->shouldNotSaveTime(((DllF7Placement*)params)->mapEventId);
        if (r == 0)
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags &= ~1;
            *(u8*)&((DllF7State*)state)->byte9 = 1;
            ((DllF7State*)state)->byte8 = 0;
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
