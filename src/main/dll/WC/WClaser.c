#include "main/dll/WC/WClaser.h"
#include "main/dll/WC/WCpressureSwitch.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/obj_placement.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int Obj_GetPlayerObject(void);
extern void objSetSlot(int *obj, int slot);
extern void objHitDetectFn_80062e84(int player, int hitObj, int mode);
extern void objRenderFn_8003b8f4(f32 scale);
extern void fn_80065574(int a, int *obj, int b);
extern void fn_80296BBC(int player);
extern void buttonDisable(int controller, int mask);
extern void textureFree(void *resource);

extern MapEventInterface **gMapEventInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern ModgfxInterface **gModgfxInterface;

extern f32 timeDelta;
extern u8 lbl_803DDC78;
extern f32 lbl_803E5CEC;
extern f32 lbl_803E5CF0;
extern f32 lbl_803E5CF4;
extern f32 lbl_803E5CF8;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D04;
extern f32 lbl_803E5D08;

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S8(obj, offset) (*(s8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))
#define OBJ_F32(obj, offset) (*(f32 *)((u8 *)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define MAP_EVENT_TEST(mapId, eventId) \
    (*gMapEventInterface)->getAnimEvent((mapId), (eventId))
#define MAP_EVENT_SET(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))
#define SCREEN_TRANSITION_START(kind, value) \
    (*gScreenTransitionInterface)->step((kind), (value))

typedef struct Dll1FBSetup {
    ObjPlacement base;
    s8 yawByte;
    s8 baseMove;
    s16 triggerMode;
    s16 objectParam;
} Dll1FBSetup;

typedef struct WMGalleonSetup {
    ObjPlacement base;
    s8 yawByte;
} WMGalleonSetup;

typedef struct WMSeqObjectSetup {
    ObjPlacement base;
    s8 yawByte;
    s8 setupType;
} WMSeqObjectSetup;

typedef struct WMGalleonState {
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    u8 mapEventsLatched;
    u8 pad0D;
    s16 savedYaw;
} WMGalleonState;

typedef struct Dll1FBState {
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

void WM_Galleon_update(int *obj)
{
    int player;
    WMGalleonState *state;
    int gameBitA4;

    if (GameBit_Get(0x78) != 0) {
        return;
    }

    if (OBJ_S16(obj, 0x46) == 0x188) {
        OBJ_U8(obj, 0x36) = 0x80;
        return;
    }

    player = Obj_GetPlayerObject();
    state = (WMGalleonState *)OBJ_PTR(obj, 0xb8);

    if (GameBit_Get(0x429) != 0) {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) != 0) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 0);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 0);
        }
    } else if ((GameBit_Get(0xd0) == 0) && ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) == 0)) {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
    }

    if (GameBit_Get(0xd0) == 0) {
        if ((state->mapEventsLatched == 0) && (GameBit_Get(0x429) == 0)) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
            state->mapEventsLatched = 1;
        }
    } else {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 4) == 0) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 4, 1);
        }
        if (state->mapEventsLatched != 0) {
            state->mapEventsLatched = 0;
        }
    }

    gameBitA4 = GameBit_Get(0xa4);
    if (gameBitA4 != 0) {
        OBJ_S32(obj, 0xf4) = 10;
    }
    if (gameBitA4 == 0) {
        OBJ_F32(player, 0xc) = lbl_803E5CEC;
        OBJ_F32(player, 0x10) = lbl_803E5CF0;
        OBJ_F32(player, 0x14) = lbl_803E5CF4;
        objHitDetectFn_80062e84(player, (int)obj, 0);
        fn_80296BBC(player);
        OBJ_S32(obj, 0xf8) = 1;
    } else if (OBJ_S32(obj, 0xf8) == 1) {
        OBJ_F32(obj, 0xc) = state->savedX;
        OBJ_F32(obj, 0x10) = state->savedY;
        OBJ_F32(obj, 0x14) = state->savedZ;
        OBJ_S16(obj, 0) = state->savedYaw;
        OBJECT_TRIGGER_REFRESH(0, obj, -1);
        OBJ_S32(obj, 0xf8) = 2;
    }
}

void WM_Galleon_init(int *obj, WMGalleonSetup *setup)
{
    WMGalleonState *state;
    int i;

    state = (WMGalleonState *)OBJ_PTR(obj, 0xb8);
    if (GameBit_Get(0x78) != 0) {
        return;
    }
    if (OBJ_S16(obj, 0x46) == 0x188) {
        return;
    }
    objSetSlot(obj, 0x5a);
    ((GameObject *)obj)->animEventCallback = (void *)WM_Galleon_SeqFn;
    OBJ_S16(obj, 0) = (s16)(setup->yawByte << 8);
    OBJ_S32(obj, 0xf4) = 9;
    state->savedX = OBJ_F32(obj, 0xc);
    state->savedY = OBJ_F32(obj, 0x10);
    state->savedZ = OBJ_F32(obj, 0x14);
    state->savedYaw = OBJ_S16(obj, 0);
    fn_80065574(0, obj, 0);
    for (i = 0; i < 5; i++) {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), i, 0);
    }
    GameBit_Set(0xa4, 1);
}

void WM_Galleon_release(void) {}
void WM_Galleon_initialise(void) {}

int WM_seqobject_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int i;

    for (i = 0; i < (int)animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == 1) {
            lbl_803DDC78 = (u8)(1 - lbl_803DDC78);
        }
    }
    ((u8 *)animUpdate)[0x80] = 0;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int WM_seqobject_getExtraSize(void) { return 1; }
int WM_seqobject_getObjectTypeId(void) { return 0; }
void WM_seqobject_free(void) {}

void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;

    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E5CF8);
    }
}

void WM_seqobject_hitDetect(void) {}

void WM_seqobject_update(int *obj)
{
    int count;
    int countdown;
    int *objects;
    int found;
    int i;
    int setupType;
    WMSeqObjectSetup *setup;

    setup = (WMSeqObjectSetup *)OBJ_PTR(obj, 0x4c);
    setupType = setup->setupType;
    switch (setupType) {
    case 8:
        break;
    case 0:
    if (OBJ_S32(obj, 0xf4) != 0) {
        return;
    }
    if (GameBit_Get(0xa4) != 0) {
        return;
    }
    if (GameBit_Get(0x78) != 0) {
        return;
    }

    objects = (int *)ObjGroup_GetObjects(6, &count);
    found = 0;
    for (i = 0; i < count; i++) {
        if (OBJ_S16(*(int **)(objects + i), 0x46) == 0x139) {
            found = 1;
        }
    }

    if (found != 0) {
        if (OBJ_S32(obj, 0xf8) == 0) {
            OBJECT_TRIGGER_REFRESH(0, obj, -1);
            OBJ_S32(obj, 0xf4) = 1;
            GameBit_Set(0xa4, 1);
        } else {
            SCREEN_TRANSITION_START(0x50, 1);
        }
    } else {
        OBJ_S32(obj, 0xf8) = 0x14;
        SCREEN_TRANSITION_START(0x50, 1);
    }

    countdown = OBJ_S32(obj, 0xf8) - 1;
    OBJ_S32(obj, 0xf8) = countdown;
    if (countdown < 0) {
        OBJ_S32(obj, 0xf8) = 0;
    }
    break;
    }
}

void WM_seqobject_init(int *obj, s8 *def)
{
    s16 angle;
    WMSeqObjectSetup *setup = (WMSeqObjectSetup *)def;

    angle = (s16)((s32)setup->yawByte << 8);
    OBJ_S16(obj, 0) = angle;
    ((GameObject *)obj)->animEventCallback = (void *)WM_seqobject_SeqFn;
    OBJ_S32(obj, 0xf8) = 0x14;
}

void WM_seqobject_release(void) {}
void WM_seqobject_initialise(void) {}

int dll_1FB_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate)
{
    Dll1FBState *state = (Dll1FBState *)OBJ_PTR(obj, 0xb8);
    s16 mode = state->triggerMode;
    u8 flags;

    if ((mode == 1) || (mode == 2)) {
        flags = (u8)(OBJ_U8(obj, 0xaf) | 8);
        OBJ_U8(obj, 0xaf) = flags;
    }
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int dll_1FB_getExtraSize_ret_12(void) { return 0xc; }
int dll_1FB_getObjectTypeId(void) { return 0; }
void dll_1FB_free_nop(void) {}

void dll_1FB_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    Dll1FBState *state = (Dll1FBState *)OBJ_PTR(obj, 0xb8);

    if (visible == 0) {
        return;
    }
    switch (state->hideModel) {
    case 0:
        ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5D00);
        break;
    }
}

void dll_1FB_hitDetect_nop(void) {}

void dll_1FB_update(int *obj)
{
    Dll1FBState *state = (Dll1FBState *)OBJ_PTR(obj, 0xb8);

    if (((OBJ_U8(obj, 0xaf) & 1) != 0) && (state->triggerMode == 2) &&
        (GameBit_Get(0x9ad) == 0)) {
        OBJECT_TRIGGER_REFRESH(4, obj, -1);
        buttonDisable(0, 0x100);
        GameBit_Set(0x9ad, 1);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        ((int)obj, lbl_803E5D04, timeDelta, NULL);
}

void dll_1FB_init(int *obj, u8 *def)
{
    Dll1FBState *state;
    Dll1FBSetup *setup;

    state = (Dll1FBState *)OBJ_PTR(obj, 0xb8);
    setup = (Dll1FBSetup *)def;
    ObjMsg_AllocQueue(obj, 4);
    ((GameObject *)obj)->animEventCallback = (void *)dll_1FB_SeqFn;
    OBJ_S16(obj, 0) = (s16)(setup->yawByte << 8);
    OBJ_S16(obj, 2) = setup->objectParam;
    state->baseMove = setup->baseMove;
    state->triggerMode = setup->triggerMode;
    ObjAnim_SetCurrentMove((int)obj, (int)state->baseMove + 0x100, lbl_803E5D08, 0);
}

void dll_1FB_release_nop(void) {}
void dll_1FB_initialise_nop(void) {}

int LaserBeam_getExtraSize(void) { return 0x50; }
int LaserBeam_getObjectTypeId(void) { return 0; }

void LaserBeam_init(int *obj)
{
    void **state;

    state = (void **)OBJ_PTR(obj, 0xb8);
    (*gModgfxInterface)->detachSource(obj);
    if (state[0] != 0) {
        textureFree(state[0]);
        state[0] = 0;
    }
}

void LaserBeam_render(void) {}
void LaserBeam_hitDetect(void) {}
