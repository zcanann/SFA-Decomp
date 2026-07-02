/* DLL 0x01FB — WCLaser render object (WarpZone cannon laser). TU: 0x801F0900–0x801F0AE4. */
#include "main/obj_placement.h"
#include "main/resource.h"

/* WM_ObjCreator per-object extra state (four s16 slots). */
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

/* WM_Galleon_getExtraSize == 0x10. */
typedef struct WmGalleonState
{
    u8 pad00[0xC];
    u8 active; /* 0x0c: cleared on a non-map-change free */
    u8 pad0D[3];
} WmGalleonState;

STATIC_ASSERT(sizeof(WmGalleonState) == 0x10);

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

#include "main/dll/WC/dll_01F9_wmobjcreator.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
extern void buttonDisable(int port, u32 mask);
#define PAD_BUTTON_A 0x100
extern f32 timeDelta;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D04;
extern f32 lbl_803E5D08;

#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))

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
    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5D00);
}

void dll_1FB_hitDetect_nop(void)
{
}

void dll_1FB_update(int* obj)
{
    Dll1FBState* state = (Dll1FBState*)((GameObject*)obj)->extra;

    if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0) && (state->triggerMode == 2) &&
        (GameBit_Get(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE) == 0))
    {
        OBJECT_TRIGGER_REFRESH(4, obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
        GameBit_Set(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE, 1);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        ((int)obj, lbl_803E5D04, timeDelta, NULL);
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
