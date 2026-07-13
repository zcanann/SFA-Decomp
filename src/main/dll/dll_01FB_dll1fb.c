/* DLL 0x01FB — WCLaser render object (WarpZone cannon laser). TU: 0x801F0900–0x801F0AE4. */
#include "main/obj_placement.h"
#include "main/pad_api.h"
#include "main/resource.h"
#include "main/frame_timing.h"
#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/dll/dll1fbsetup_struct.h"
#include "main/dll/wmgalleonsetup_struct.h"
#include "main/dll/wmseqobjectsetup_struct.h"
#include "main/dll/wmgalleonstate_struct.h"
#include "main/dll/dll1fbstate_struct.h"

STATIC_ASSERT(sizeof(WmObjCreatorState) == 0x8);

STATIC_ASSERT(offsetof(WmObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnJitter) == 0x1F);
STATIC_ASSERT(sizeof(WmObjCreatorPlacement) == 0x24);

STATIC_ASSERT(sizeof(WmGalleonState) == 0x10);

#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#define PAD_BUTTON_A 0x100
__declspec(section ".sdata2") f32 lbl_803E5D00 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5D04 = 0.01f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5D08 = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E5D0C = 0.0f;
#pragma explicit_zero_data off

#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))

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

int dll_1FB_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    Dll1FBState* state = (Dll1FBState*)((GameObject*)obj)->extra;
    s16 mode = state->triggerMode;
    u8 flags;

    if ((mode == 1) || (mode == 2))
    {
        flags = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = flags;
    }
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int dll_1FB_getExtraSize_ret_12(void) { return 0xc; }
int dll_1FB_getObjectTypeId(void) { return 0; }

void dll_1FB_free_nop(void)
{
}

void dll_1FB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    Dll1FBState* state = (Dll1FBState*)((GameObject*)obj)->extra;

    if (visible == 0 || state->hideModel != 0u)
    {
        return;
    }
    ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E5D00);
}

void dll_1FB_hitDetect_nop(void)
{
}

void dll_1FB_update(int* obj)
{
    Dll1FBState* state = (Dll1FBState*)((GameObject*)obj)->extra;

    if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0) && (state->triggerMode == 2) &&
        (mainGetBit(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE) == 0))
    {
        OBJECT_TRIGGER_REFRESH(4, obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
        mainSetBits(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE, 1);
    }
    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E5D04, timeDelta, NULL);
}

void dll_1FB_init(int* obj, u8* def)
{
    Dll1FBState* state;
    Dll1FBSetup* setup;

    state = (Dll1FBState*)((GameObject*)obj)->extra;
    setup = (Dll1FBSetup*)def;
    ObjMsg_AllocQueue(obj, 4);
    ((GameObject*)obj)->animEventCallback = dll_1FB_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(setup->yawByte << 8);
    ((GameObject*)obj)->anim.rotY = setup->objectParam;
    state->baseMove = setup->baseMove;
    state->triggerMode = setup->triggerMode;
    ObjAnim_SetCurrentMove((int)obj, state->baseMove + 0x100, lbl_803E5D08, 0);
}

void dll_1FB_release_nop(void)
{
}

void dll_1FB_initialise_nop(void)
{
}
