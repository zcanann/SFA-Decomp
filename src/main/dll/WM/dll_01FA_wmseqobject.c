/* DLL 0x01FA - wmseqobject / WM_ObjCreator group. TU: 0x801EFF7C-0x801F02F0. */
#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/obj_placement.h"

/* TU-boundary copies of the WM_ObjCreator records (canonical copies
   in dll_01F9_wmobjcreator.c) */
typedef struct WmObjCreatorState
{
    s16 gameBit; /* 0x00: spawn gate, -1 = always */
    s16 spawnPeriod; /* 0x02 */
    s16 spawnTimer; /* 0x04 */
    s16 spawnJitter; /* 0x06: randomGetRange(0, jitter) added per cycle */
} WmObjCreatorState;

STATIC_ASSERT(sizeof(WmObjCreatorState) == 0x8);

typedef struct WmObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnPeriod;
    s8 yaw;
    s8 spawnJitter;
    u8 pad20[4];
} WmObjCreatorPlacement;

STATIC_ASSERT(offsetof(WmObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnJitter) == 0x1F);
STATIC_ASSERT(sizeof(WmObjCreatorPlacement) == 0x24);

typedef struct WmGalleonState
{
    u8 pad00[0xC];
    u8 active; /* 0x0c: cleared on a non-map-change free */
    u8 pad0D[3];
} WmGalleonState;

STATIC_ASSERT(sizeof(WmGalleonState) == 0x10);

#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
extern u8 lbl_803DDC78;
extern f32 lbl_803E5CF8;

#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))
#define SCREEN_TRANSITION_START(kind, value) \
    (*gScreenTransitionInterface)->step((kind), (value))

typedef struct Dll1FBSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 baseMove;
    s16 triggerMode;
    s16 objectParam;
} Dll1FBSetup;

typedef struct WMGalleonSetup
{
    ObjPlacement base;
    s8 yawByte;
} WMGalleonSetup;

typedef struct WMSeqObjectSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 setupType;
} WMSeqObjectSetup;

typedef struct WMGalleonState
{
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    u8 mapEventsLatched;
    u8 pad0D;
    s16 savedYaw;
} WMGalleonState;

typedef struct Dll1FBState
{
    u8 pad00[4];
    s16 baseMove;
    s16 triggerMode;
    u8 pad08;
    u8 hideModel;
    u8 pad0A[2];
} Dll1FBState;

STATIC_ASSERT(sizeof(Dll1FBState) == 0xc);
STATIC_ASSERT(offsetof(Dll1FBState, baseMove) == 0x04);
STATIC_ASSERT(offsetof(Dll1FBState, triggerMode) == 0x06);
STATIC_ASSERT(offsetof(Dll1FBState, hideModel) == 0x09);
STATIC_ASSERT(sizeof(WMGalleonState) == 0x10);
STATIC_ASSERT(offsetof(WMGalleonState, savedX) == 0x00);
STATIC_ASSERT(offsetof(WMGalleonState, savedY) == 0x04);
STATIC_ASSERT(offsetof(WMGalleonState, savedZ) == 0x08);
STATIC_ASSERT(offsetof(WMGalleonState, mapEventsLatched) == 0x0C);
STATIC_ASSERT(offsetof(WMGalleonState, savedYaw) == 0x0E);
STATIC_ASSERT(offsetof(Dll1FBSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1FBSetup, baseMove) == 0x19);
STATIC_ASSERT(offsetof(Dll1FBSetup, triggerMode) == 0x1a);
STATIC_ASSERT(offsetof(Dll1FBSetup, objectParam) == 0x1c);
STATIC_ASSERT(offsetof(WMGalleonSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, setupType) == 0x19);

int WM_seqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            lbl_803DDC78 = (u8)(1 - lbl_803DDC78);
        }
    }
    animUpdate->triggerCommand = 0;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int WM_seqobject_getExtraSize(void) { return 1; }
int WM_seqobject_getObjectTypeId(void) { return 0; }

void WM_seqobject_free(void)
{
}

void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    s32 v = visible;

    if (v != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5CF8);
    }
}

void WM_seqobject_hitDetect(void)
{
}

void WM_seqobject_update(int* obj)
{
    int count;
    int countdown;
    int* objects;
    int found;
    int i;
    int setupType;
    WMSeqObjectSetup* setup;

    setup = (WMSeqObjectSetup*)OBJ_PTR(obj, 0x4c);
    setupType = setup->setupType;
    switch (setupType)
    {
    case 8:
        break;
    case 0:
        if (OBJ_S32(obj, 0xf4) != 0)
        {
            return;
        }
        if (GameBit_Get(0xa4) != 0)
        {
            return;
        }
        if (GameBit_Get(0x78) != 0)
        {
            return;
        }

        objects = (int*)ObjGroup_GetObjects(6, &count);
        found = 0;
        for (i = 0; i < count; i++)
        {
            if (OBJ_S16(*(int **)(objects + i), 0x46) == 0x139)
            {
                found = 1;
            }
        }

        if (found != 0)
        {
            if (OBJ_S32(obj, 0xf8) == 0)
            {
                OBJECT_TRIGGER_REFRESH(0, obj, -1);
                OBJ_S32(obj, 0xf4) = 1;
                GameBit_Set(0xa4, 1);
            }
            else
            {
                SCREEN_TRANSITION_START(0x50, 1);
            }
        }
        else
        {
            OBJ_S32(obj, 0xf8) = 0x14;
            SCREEN_TRANSITION_START(0x50, 1);
        }

        countdown = OBJ_S32(obj, 0xf8) - 1;
        OBJ_S32(obj, 0xf8) = countdown;
        if (countdown < 0)
        {
            OBJ_S32(obj, 0xf8) = 0;
        }
        break;
    }
}

void WM_seqobject_init(int* obj, s8* def)
{
    s16 angle;
    WMSeqObjectSetup* setup = (WMSeqObjectSetup*)def;

    angle = (s16)((s32)setup->yawByte << 8);
    OBJ_S16(obj, 0) = angle;
    ((GameObject*)obj)->animEventCallback = WM_seqobject_SeqFn;
    OBJ_S32(obj, 0xf8) = 0x14;
}

void WM_seqobject_release(void)
{
}

void WM_seqobject_initialise(void)
{
}

