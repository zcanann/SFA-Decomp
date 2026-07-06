/* DLL 0x01F8 (wmgalleon) - WM galleon and object creator [0x801EFF7C-0x801F06D8). */
#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/objseq.h"
#include "main/gamebits.h"

/* TU-boundary copies of the WM_ObjCreator records (canonical copies in
   dll_01F9_wmobjcreator.c) - this TU hosts WM_ObjCreator_init. */
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

extern void getLActions(int obj, int obj2, int action, int p4, int p5, int p6);
extern u32 lbl_803DC0F0;
extern u8 framesThisStep;
extern s8 lbl_803DDC70;
extern int* gScreensInterface;
extern u32* lbl_803DCA94;
extern void* lbl_803DDC74;
extern f32 lbl_803E5CE8;

#define WM_GALLEON_GAMEBIT_CUTSCENE_DONE 0x429
#define WM_GALLEON_GAMEBIT_CLEAR_DOOR 0xD1
#define WM_GALLEON_COMMAND_OPENED 1
#define WM_GALLEON_COMMAND_CLEAR_LACTIONS 2
#define WM_GALLEON_COMMAND_SCREEN_FADE 3
#define WM_GALLEON_COMMAND_ACTION_12 4
#define WM_GALLEON_COMMAND_ACTION_13 5
#define WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS 6
#define WM_GALLEON_COMMAND_SHOW_MODEL 7
#define WM_GALLEON_COMMAND_HIDE_MODEL 8
#define WM_GALLEON_COMMAND_ACTION_11 9
#define WM_GALLEON_ACTION_OPENED 10
#define WM_GALLEON_ACTION_11 11
#define WM_GALLEON_ACTION_12 12
#define WM_GALLEON_ACTION_13 13

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))

extern int Obj_GetPlayerObject(void);
extern void objSetSlot(int* obj, int slot);
extern void objHitDetectFn_80062e84(int player, int hitObj, int mode);
extern void fn_80065574(int a, int* obj, int b);
extern void fn_80296BBC(int player);
extern f32 lbl_803E5CEC;
extern f32 lbl_803E5CF0;
extern f32 lbl_803E5CF4;

int WM_Galleon_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;

    lbl_803DC0F0 = framesThisStep;
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case WM_GALLEON_COMMAND_OPENED:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_OPENED;
            break;
        case WM_GALLEON_COMMAND_ACTION_11:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_11;
            break;
        case WM_GALLEON_COMMAND_ACTION_12:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_12;
            break;
        case WM_GALLEON_COMMAND_ACTION_13:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_13;
            break;
        case WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS:
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 2, 0);
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 4, 0);
            GameBit_Set(WM_GALLEON_GAMEBIT_CLEAR_DOOR, 0);
            break;
        case WM_GALLEON_COMMAND_CLEAR_LACTIONS:
            getLActions(obj, obj, 0x77, 0, 0, 0);
            getLActions(obj, obj, 0x78, 0, 0, 0);
            getLActions(obj, obj, 0x80, 0, 0, 0);
            break;
        case WM_GALLEON_COMMAND_SCREEN_FADE:
            (*(void (**)(int, int, int))((u8*)*lbl_803DCA94 + 0x14))(0, 0x1e, 0x50);
            break;
        case WM_GALLEON_COMMAND_SHOW_MODEL:
            lbl_803DDC70 = 1;
            break;
        case WM_GALLEON_COMMAND_HIDE_MODEL:
            lbl_803DDC70 = 0;
            break;
        }
    }

    if (GameBit_Get(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(OBJ_U8(obj, 0x34), 2) != 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 2, 0);
        }
    }
    return 0;
}

int WM_Galleon_getExtraSize(void) { return 0x10; }
int WM_Galleon_getObjectTypeId(void) { return 0x0; }

void WM_Galleon_free(int* obj, int leavingMap)
{
    if (((GameObject*)obj)->anim.seqId != 0x188)
    {
        WmGalleonState* state = ((GameObject*)obj)->extra;
        if (state->active != 0 && leavingMap == 0)
        {
            state->active = 0;
        }
        if (lbl_803DDC74 != NULL)
        {
            Resource_Release(lbl_803DDC74);
            lbl_803DDC74 = NULL;
        }
    }
}

void WM_Galleon_render(void* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderModelAndHitVolumes(void* obj, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    if (GameBit_Get(0x78) != 0)
    {
        return;
    }
    if (visible == 0)
    {
        return;
    }
    if (((GameObject*)obj)->anim.seqId == 0x188 && ((GameObject*)((GameObject*)obj)->anim.parent)->unkF4 >= 7)
    {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E5CE8);

    if (lbl_803DDC70 != 0)
    {
        (*(void (**)(int))(*(int*)gScreensInterface + 0x4))(1);
    }
}

void WM_Galleon_hitDetect(void)
{
}

#define OBJ_F32(obj, offset) (*(f32 *)((u8 *)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define MAP_EVENT_TEST(mapId, eventId) \
    (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET(mapId, eventId, value) \
    (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))

/* neighbor-TU placement layouts (dll_01FB) shared by this unit */
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

/* NOTE: distinct from the WmGalleonState head-section copy above -
   this is the galleon TU's own state layout (the lowercase-m one is
   the WM_ObjCreator-group view of the same 0x10 block). */
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

void WM_Galleon_update(int* obj)
{
    int player;
    WMGalleonState* state;
    int gameBitA4;

    if (GameBit_Get(0x78) != 0)
    {
        return;
    }

    if (OBJ_S16(obj, 0x46) == 0x188)
    {
        OBJ_U8(obj, 0x36) = 0x80;
        return;
    }

    player = Obj_GetPlayerObject();
    state = (WMGalleonState*)OBJ_PTR(obj, 0xb8);

    if (GameBit_Get(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) != 0)
    {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) != 0)
        {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 0);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 0);
        }
    }
    else if ((GameBit_Get(0xd0) == 0) && ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) == 0))
    {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
    }

    if (GameBit_Get(0xd0) == 0)
    {
        if ((state->mapEventsLatched == 0) && (GameBit_Get(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) == 0))
        {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
            state->mapEventsLatched = 1;
        }
    }
    else
    {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 4) == 0)
        {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 4, 1);
        }
        if (state->mapEventsLatched != 0)
        {
            state->mapEventsLatched = 0;
        }
    }

    gameBitA4 = GameBit_Get(0xa4);
    if (gameBitA4 != 0)
    {
        OBJ_S32(obj, 0xf4) = 10;
    }
    if (gameBitA4 == 0)
    {
        OBJ_F32(player, 0xc) = lbl_803E5CEC;
        OBJ_F32(player, 0x10) = lbl_803E5CF0;
        OBJ_F32(player, 0x14) = lbl_803E5CF4;
        objHitDetectFn_80062e84(player, (int)obj, 0);
        fn_80296BBC(player);
        OBJ_S32(obj, 0xf8) = 1;
    }
    else if (OBJ_S32(obj, 0xf8) == 1)
    {
        OBJ_F32(obj, 0xc) = state->savedX;
        OBJ_F32(obj, 0x10) = state->savedY;
        OBJ_F32(obj, 0x14) = state->savedZ;
        OBJ_S16(obj, 0) = state->savedYaw;
        OBJECT_TRIGGER_REFRESH(0, obj, -1);
        OBJ_S32(obj, 0xf8) = 2;
    }
}

void WM_Galleon_init(int* obj, WMGalleonSetup* setup)
{
    WMGalleonState* state;
    int i;

    state = (WMGalleonState*)OBJ_PTR(obj, 0xb8);
    if (GameBit_Get(0x78) != 0)
    {
        return;
    }
    if (OBJ_S16(obj, 0x46) == 0x188)
    {
        return;
    }
    objSetSlot(obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = WM_Galleon_SeqFn;
    OBJ_S16(obj, 0) = (s16)(setup->yawByte << 8);
    OBJ_S32(obj, 0xf4) = 9;
    state->savedX = OBJ_F32(obj, 0xc);
    state->savedY = OBJ_F32(obj, 0x10);
    state->savedZ = OBJ_F32(obj, 0x14);
    state->savedYaw = OBJ_S16(obj, 0);
    fn_80065574(0, obj, 0);
    for (i = 0; i < 5; i++)
    {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), i, 0);
    }
    GameBit_Set(0xa4, 1);
}

void WM_Galleon_release(void)
{
}

void WM_Galleon_initialise(void)
{
}


/* descriptor/ptr table auto 0x80328748-0x80328898 */
extern u8 LaserBeam_free[];
extern u8 LaserBeam_getExtraSize[];
extern u8 LaserBeam_getObjectTypeId[];
extern u8 LaserBeam_hitDetect[];
extern u8 LaserBeam_init[];
extern u8 LaserBeam_initialise[];
extern u8 LaserBeam_release[];
extern u8 LaserBeam_render[];
extern u8 LaserBeam_update[];
extern u8 WM_seqobject_free[];
extern u8 WM_seqobject_getExtraSize[];
extern u8 WM_seqobject_getObjectTypeId[];
extern u8 WM_seqobject_hitDetect[];
extern u8 WM_seqobject_init[];
extern u8 WM_seqobject_initialise[];
extern u8 WM_seqobject_release[];
extern u8 WM_seqobject_render[];
extern u8 WM_seqobject_update[];
extern u8 dll_1FB_free_nop[];
extern u8 dll_1FB_getExtraSize_ret_12[];
extern u8 dll_1FB_getObjectTypeId[];
extern u8 dll_1FB_hitDetect_nop[];
extern u8 dll_1FB_init[];
extern u8 dll_1FB_initialise_nop[];
extern u8 dll_1FB_release_nop[];
extern u8 dll_1FB_render[];
extern u8 dll_1FB_update[];
extern u8 dll_1FF_free_nop[];
extern u8 dll_1FF_getExtraSize_ret_8[];
extern u8 dll_1FF_getObjectTypeId[];
extern u8 dll_1FF_hitDetect_nop[];
extern u8 dll_1FF_init[];
extern u8 dll_1FF_initialise_nop[];
extern u8 dll_1FF_release_nop[];
extern u8 dll_1FF_render[];
extern u8 dll_1FF_update[];
extern u8 pressureswitch_free[];
extern u8 pressureswitch_getExtraSize[];
extern u8 pressureswitch_getObjectTypeId[];
extern u8 pressureswitch_hitDetect[];
extern u8 pressureswitch_init[];
extern u8 pressureswitch_initialise[];
extern u8 pressureswitch_release[];
extern u8 pressureswitch_render[];
extern u8 pressureswitch_update[];
extern u8 wmlasertarget_free[];
extern u8 wmlasertarget_getExtraSize[];
extern u8 wmlasertarget_getObjectTypeId[];
extern u8 wmlasertarget_hitDetect[];
extern u8 wmlasertarget_init[];
extern u8 wmlasertarget_initialise[];
extern u8 wmlasertarget_release[];
extern u8 wmlasertarget_render[];
extern u8 wmlasertarget_update[];

u32 gWM_seqobjectObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)WM_seqobject_initialise, (u32)WM_seqobject_release, 0x00000000, (u32)WM_seqobject_init, (u32)WM_seqobject_update, (u32)WM_seqobject_hitDetect, (u32)WM_seqobject_render, (u32)WM_seqobject_free, (u32)WM_seqobject_getObjectTypeId, (u32)WM_seqobject_getExtraSize };
u32 dll_1FB[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_1FB_initialise_nop, (u32)dll_1FB_release_nop, 0x00000000, (u32)dll_1FB_init, (u32)dll_1FB_update, (u32)dll_1FB_hitDetect_nop, (u32)dll_1FB_render, (u32)dll_1FB_free_nop, (u32)dll_1FB_getObjectTypeId, (u32)dll_1FB_getExtraSize_ret_12 };
u32 gLaserBeamObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)LaserBeam_initialise, (u32)LaserBeam_release, 0x00000000, (u32)LaserBeam_free, (u32)LaserBeam_update, (u32)LaserBeam_hitDetect, (u32)LaserBeam_render, (u32)LaserBeam_init, (u32)LaserBeam_getObjectTypeId, (u32)LaserBeam_getExtraSize };
u32 gPressureSwitchObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)pressureswitch_initialise, (u32)pressureswitch_release, 0x00000000, (u32)pressureswitch_init, (u32)pressureswitch_update, (u32)pressureswitch_hitDetect, (u32)pressureswitch_render, (u32)pressureswitch_free, (u32)pressureswitch_getObjectTypeId, (u32)pressureswitch_getExtraSize };
u32 dll_1FF[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_1FF_initialise_nop, (u32)dll_1FF_release_nop, 0x00000000, (u32)dll_1FF_init, (u32)dll_1FF_update, (u32)dll_1FF_hitDetect_nop, (u32)dll_1FF_render, (u32)dll_1FF_free_nop, (u32)dll_1FF_getObjectTypeId, (u32)dll_1FF_getExtraSize_ret_8 };
u32 gWM_LaserTargetObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)wmlasertarget_initialise, (u32)wmlasertarget_release, 0x00000000, (u32)wmlasertarget_init, (u32)wmlasertarget_update, (u32)wmlasertarget_hitDetect, (u32)wmlasertarget_render, (u32)wmlasertarget_free, (u32)wmlasertarget_getObjectTypeId, (u32)wmlasertarget_getExtraSize };
