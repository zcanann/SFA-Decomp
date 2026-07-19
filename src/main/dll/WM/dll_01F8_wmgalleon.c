/* DLL 0x01F8 (wmgalleon) - WM galleon and object creator [0x801EFF7C-0x801F06D8). */
#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/object_descriptor.h"
#include "main/render_lactions_api.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0011_screens.h"
#include "main/track_dolphin_api.h"
#include "main/dll/dll1fbsetup_struct.h"
#include "main/dll/wmgalleonsetup_struct.h"
#include "main/dll/wmseqobjectsetup_struct.h"
#include "main/dll/wmgalleonstate_struct.h"
#include "main/dll/dll1fbstate_struct.h"
#include "main/dll/WM/dll_01FA_wmseqobject.h"
#include "main/dll/WM/dll_01FD_wmlasertarget.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_01FE_pressureswitch.h"

u32 lbl_803DC0F0 = 3;

STATIC_ASSERT(sizeof(WmObjCreatorState) == 0x8);

STATIC_ASSERT(offsetof(WmObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnJitter) == 0x1F);
STATIC_ASSERT(sizeof(WmObjCreatorPlacement) == 0x24);

STATIC_ASSERT(sizeof(WmGalleonState) == 0x10);

/* neighbor-TU placement layouts (dll_01FB) shared by this unit */

/* NOTE: distinct from the WmGalleonState head-section copy above -
   this is the galleon TU's own state layout (the lowercase-m one is
   the WM_ObjCreator-group view of the same 0x10 block). */

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

#define WM_GALLEON_GAMEBIT_CUTSCENE_DONE    0x429
#define WM_GALLEON_GAMEBIT_CLEAR_DOOR       0xD1
#define WM_GALLEON_COMMAND_OPENED           1
#define WM_GALLEON_COMMAND_CLEAR_LACTIONS   2
#define WM_GALLEON_COMMAND_SCREEN_FADE      3
#define WM_GALLEON_COMMAND_ACTION_12        4
#define WM_GALLEON_COMMAND_ACTION_13        5
#define WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS 6
#define WM_GALLEON_COMMAND_SHOW_MODEL       7
#define WM_GALLEON_COMMAND_HIDE_MODEL       8
#define WM_GALLEON_COMMAND_ACTION_11        9
#define WM_GALLEON_ACTION_OPENED            10
#define WM_GALLEON_ACTION_11                11
#define WM_GALLEON_ACTION_12                12
#define WM_GALLEON_ACTION_13                13

#define OBJ_U8(obj, offset)  (*(u8*)((u8*)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16*)((u8*)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32*)((u8*)(obj) + (offset)))
#define OBJ_F32(obj, offset) (*(f32*)((u8*)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void**)((u8*)(obj) + (offset)))

#define MAP_EVENT_TEST(mapId, eventId)            (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET(mapId, eventId, value)      (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))

void* lbl_803DDC74;
extern u32* lbl_803DCA94;
s8 lbl_803DDC70;
void WM_Galleon_initialise(void);
void WM_Galleon_release(void);
void WM_Galleon_init(int* obj, WMGalleonSetup* setup);
void WM_Galleon_update(int* obj);
void WM_Galleon_hitDetect(void);
int WM_Galleon_getObjectTypeId(void);
int WM_Galleon_getExtraSize(void);

ObjectDescriptor gWM_GalleonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_Galleon_initialise,
    (ObjectDescriptorCallback)WM_Galleon_release,
    0,
    (ObjectDescriptorCallback)WM_Galleon_init,
    (ObjectDescriptorCallback)WM_Galleon_update,
    (ObjectDescriptorCallback)WM_Galleon_hitDetect,
    (ObjectDescriptorCallback)WM_Galleon_render,
    (ObjectDescriptorCallback)WM_Galleon_free,
    (ObjectDescriptorCallback)WM_Galleon_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)WM_Galleon_getExtraSize,
};

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
            mainSetBits(WM_GALLEON_GAMEBIT_CLEAR_DOOR, 0);
            break;
        case WM_GALLEON_COMMAND_CLEAR_LACTIONS:
            getLActions((void*)obj, (void*)obj, 0x77, 0, 0, 0);
            getLActions((void*)obj, (void*)obj, 0x78, 0, 0, 0);
            getLActions((void*)obj, (void*)obj, 0x80, 0, 0, 0);
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

    if (mainGetBit(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(OBJ_U8(obj, 0x34), 2) != 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(OBJ_U8(obj, 0x34), 2, 0);
        }
    }
    return 0;
}

int WM_Galleon_getExtraSize(void)
{
    return 0x10;
}
int WM_Galleon_getObjectTypeId(void)
{
    return 0x0;
}

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

void WM_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0)
    {
        return;
    }
    if (visible == 0)
    {
        return;
    }
    if ((obj)->anim.seqId == 0x188 && ((GameObject*)(obj)->anim.parent)->userData1 >= 7)
    {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);

    if (lbl_803DDC70 != 0)
    {
        gScreensInterface->vtable->show(1);
    }
}

void WM_Galleon_hitDetect(void)
{
}

void WM_Galleon_update(int* obj)
{
    int player;
    WMGalleonState* state;
    int gameBitA4;

    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0)
    {
        return;
    }

    if (OBJ_S16(obj, 0x46) == 0x188)
    {
        OBJ_U8(obj, 0x36) = 0x80;
        return;
    }

    player = (int)Obj_GetPlayerObject();
    state = (WMGalleonState*)OBJ_PTR(obj, 0xb8);

    if (mainGetBit(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) != 0)
    {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) != 0)
        {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 0);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 0);
        }
    }
    else if ((mainGetBit(GAMEBIT_WM_GalleonRelated00D0) == 0) && ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) == 0))
    {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
    }

    if (mainGetBit(GAMEBIT_WM_GalleonRelated00D0) == 0)
    {
        if ((state->mapEventsLatched == 0) && (mainGetBit(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) == 0))
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

    gameBitA4 = mainGetBit(GAMEBIT_WM_GalleonRelated00A4);
    if (gameBitA4 != 0)
    {
        OBJ_S32(obj, 0xf4) = 10;
    }
    if (gameBitA4 == 0)
    {
        ((GameObject*)player)->anim.localPosX = -121.0f;
        ((GameObject*)player)->anim.localPosY = 116.0f;
        ((GameObject*)player)->anim.localPosZ = 5.0f;
        objHitDetectFn_80062e84((GameObject*)player, (GameObject*)obj, 0);
        fn_80296BBC((GameObject*)(player));
        OBJ_S32(obj, 0xf8) = 1;
    }
    else if (OBJ_S32(obj, 0xf8) == 1)
    {
        ((GameObject*)obj)->anim.localPosX = state->savedX;
        ((GameObject*)obj)->anim.localPosY = state->savedY;
        ((GameObject*)obj)->anim.localPosZ = state->savedZ;
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
    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0)
    {
        return;
    }
    if (OBJ_S16(obj, 0x46) == 0x188)
    {
        return;
    }
    objSetSlot((GameObject*)obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = WM_Galleon_SeqFn;
    OBJ_S16(obj, 0) = (s16)(setup->yawByte << 8);
    OBJ_S32(obj, 0xf4) = 9;
    state->savedX = ((GameObject*)obj)->anim.localPosX;
    state->savedY = ((GameObject*)obj)->anim.localPosY;
    state->savedZ = ((GameObject*)obj)->anim.localPosZ;
    state->savedYaw = OBJ_S16(obj, 0);
    fn_80065574(0, (GameObject*)(obj), 0);
    for (i = 0; i < 5; i++)
    {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), i, 0);
    }
    mainSetBits(GAMEBIT_WM_GalleonRelated00A4, 1);
}

void WM_Galleon_release(void)
{
}

void WM_Galleon_initialise(void)
{
}

/* descriptor/ptr table auto 0x80328748-0x80328898 */
extern void LaserBeam_init(s16* obj, char* arg);
extern int LaserBeam_getExtraSize(void);
extern int LaserBeam_getObjectTypeId(void);
extern void LaserBeam_hitDetect(void);
extern void LaserBeam_free(int* obj);
extern void LaserBeam_initialise(void);
extern void LaserBeam_release(void);
extern void LaserBeam_render(void);
extern void LaserBeam_update(int obj2);
extern void dll_1FB_free_nop(void);
extern int dll_1FB_getExtraSize_ret_12(void);
extern int dll_1FB_getObjectTypeId(void);
extern void dll_1FB_hitDetect_nop(void);
extern void dll_1FB_init(int* obj, u8* def);
extern void dll_1FB_initialise_nop(void);
extern void dll_1FB_release_nop(void);
extern void dll_1FB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void dll_1FB_update(int* obj);
extern void dll_1FF_free_nop(void);
extern int dll_1FF_getExtraSize_ret_8(void);
extern int dll_1FF_getObjectTypeId(int* obj);
extern void dll_1FF_hitDetect_nop(void);
extern void dll_1FF_init(s16* a, s8* b);
extern void dll_1FF_initialise_nop(void);
extern void dll_1FF_release_nop(void);
extern void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
extern void dll_1FF_update(int obj);

ObjectDescriptor gWM_seqobjectObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_seqobject_initialise,
    (ObjectDescriptorCallback)WM_seqobject_release,
    0,
    (ObjectDescriptorCallback)WM_seqobject_init,
    (ObjectDescriptorCallback)WM_seqobject_update,
    (ObjectDescriptorCallback)WM_seqobject_hitDetect,
    (ObjectDescriptorCallback)WM_seqobject_render,
    (ObjectDescriptorCallback)WM_seqobject_free,
    (ObjectDescriptorCallback)WM_seqobject_getObjectTypeId,
    WM_seqobject_getExtraSize,
};
u32 dll_1FB[14] = {0x00000000,
                   0x00000000,
                   0x00000000,
                   0x00090000,
                   (u32)dll_1FB_initialise_nop,
                   (u32)dll_1FB_release_nop,
                   0x00000000,
                   (u32)dll_1FB_init,
                   (u32)dll_1FB_update,
                   (u32)dll_1FB_hitDetect_nop,
                   (u32)dll_1FB_render,
                   (u32)dll_1FB_free_nop,
                   (u32)dll_1FB_getObjectTypeId,
                   (u32)dll_1FB_getExtraSize_ret_12};
ObjectDescriptor gLaserBeamObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)LaserBeam_initialise,
    (ObjectDescriptorCallback)LaserBeam_release,
    0,
    (ObjectDescriptorCallback)LaserBeam_init,
    (ObjectDescriptorCallback)LaserBeam_update,
    (ObjectDescriptorCallback)LaserBeam_hitDetect,
    (ObjectDescriptorCallback)LaserBeam_render,
    (ObjectDescriptorCallback)LaserBeam_free,
    (ObjectDescriptorCallback)LaserBeam_getObjectTypeId,
    LaserBeam_getExtraSize,
};
ObjectDescriptor gPressureSwitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)PressureSwitch_initialise,
    (ObjectDescriptorCallback)PressureSwitch_release,
    0,
    (ObjectDescriptorCallback)PressureSwitch_init,
    (ObjectDescriptorCallback)PressureSwitch_update,
    (ObjectDescriptorCallback)PressureSwitch_hitDetect,
    (ObjectDescriptorCallback)PressureSwitch_render,
    (ObjectDescriptorCallback)PressureSwitch_free,
    (ObjectDescriptorCallback)PressureSwitch_getObjectTypeId,
    PressureSwitch_getExtraSize,
};
u32 dll_1FF[14] = {0x00000000,
                   0x00000000,
                   0x00000000,
                   0x00090000,
                   (u32)dll_1FF_initialise_nop,
                   (u32)dll_1FF_release_nop,
                   0x00000000,
                   (u32)dll_1FF_init,
                   (u32)dll_1FF_update,
                   (u32)dll_1FF_hitDetect_nop,
                   (u32)dll_1FF_render,
                   (u32)dll_1FF_free_nop,
                   (u32)dll_1FF_getObjectTypeId,
                   (u32)dll_1FF_getExtraSize_ret_8};
ObjectDescriptor gWM_LaserTargetObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_LaserTarget_initialise,
    (ObjectDescriptorCallback)WM_LaserTarget_release,
    0,
    (ObjectDescriptorCallback)WM_LaserTarget_init,
    (ObjectDescriptorCallback)WM_LaserTarget_update,
    (ObjectDescriptorCallback)WM_LaserTarget_hitDetect,
    (ObjectDescriptorCallback)WM_LaserTarget_render,
    (ObjectDescriptorCallback)WM_LaserTarget_free,
    (ObjectDescriptorCallback)WM_LaserTarget_getObjectTypeId,
    WM_LaserTarget_getExtraSize,
};
