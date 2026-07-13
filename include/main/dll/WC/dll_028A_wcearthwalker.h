#ifndef MAIN_DLL_WC_DLL_028A_WCEARTHWALKER_H
#define MAIN_DLL_WC_DLL_028A_WCEARTHWALKER_H

#include "global.h"
#include "main/game_object.h"
#include "main/objHitReact.h"
#include "main/objanim_update.h"
#include "main/dll/curve_walker.h"

/* Extra block used by the DLL 0x28B state handlers compiled into this TU.
 * This is distinct from the EarthWalker's own EarthWalkerState below. */
typedef struct Dll28BAiState {
    u8 unk0[0x9B0 - 0x0];
    RomCurveWalker route;
    f32 playerDistance;
    f32 randomTimer;
    u8 flagsAC0;
    u8 unkAC1[0xAC8 - 0xAC1];
} Dll28BAiState;

STATIC_ASSERT(offsetof(Dll28BAiState, route) == 0x9B0);
STATIC_ASSERT(offsetof(Dll28BAiState, route.posX) == 0xA18);
STATIC_ASSERT(offsetof(Dll28BAiState, playerDistance) == 0xAB8);

typedef struct EarthWalkerState
{
    u8 pad000[0x600];
    u8 animPhase;
    u8 pad601[0x610 - 0x601];
    u8 hitTriggerId;
    u8 moveLibFlags611;
    u8 pad612[0x624 - 0x612];
    u8 eyeAnimState[0x654 - 0x624];
    f32 hitReactStepScale;
    u8 interactionState;
    u8 flags;
    u8 hitReactState;
    u8 encounterType;
    s8 lastTriggeredState;
    u8 pad65D[0x660 - 0x65D];
} EarthWalkerState;

typedef struct EarthWalkerObject
{
    union
    {
        ObjAnimComponent anim;
        struct
        {
            s16 facingAngle;
            u8 pad02[0xA0 - 0x02];
            s16 currentMove;
            u8 padA2[0xAC - 0xA2];
            s8 mapEventId;
            u8 padAD[0xAF - 0xAD];
            u8 statusFlags;
        };
    };
    u8 padB0[0xB8 - sizeof(ObjAnimComponent)];
    EarthWalkerState* state;
    void* animEventCallback;
} EarthWalkerObject;

STATIC_ASSERT(sizeof(EarthWalkerState) == 0x660);
STATIC_ASSERT(offsetof(EarthWalkerState, animPhase) == 0x600);
STATIC_ASSERT(offsetof(EarthWalkerState, hitTriggerId) == 0x610);
STATIC_ASSERT(offsetof(EarthWalkerState, eyeAnimState) == 0x624);
STATIC_ASSERT(offsetof(EarthWalkerState, hitReactStepScale) == 0x654);
STATIC_ASSERT(offsetof(EarthWalkerState, interactionState) == 0x658);
STATIC_ASSERT(offsetof(EarthWalkerState, flags) == 0x659);
STATIC_ASSERT(offsetof(EarthWalkerState, hitReactState) == 0x65A);
STATIC_ASSERT(offsetof(EarthWalkerState, encounterType) == 0x65B);
STATIC_ASSERT(offsetof(EarthWalkerState, lastTriggeredState) == 0x65C);
STATIC_ASSERT(offsetof(EarthWalkerObject, anim) == 0x00);
STATIC_ASSERT(offsetof(EarthWalkerObject, facingAngle) == 0x00);
STATIC_ASSERT(offsetof(EarthWalkerObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(EarthWalkerObject, mapEventId) == offsetof(ObjAnimComponent, mapEventSlot));
STATIC_ASSERT(offsetof(EarthWalkerObject, statusFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(EarthWalkerObject, state) == 0xB8);
STATIC_ASSERT(offsetof(EarthWalkerObject, animEventCallback) == 0xBC);

extern ObjHitReactEntry gEarthWalkerHitReactEntries[];
extern f32 gEarthWalkerMoveStartProgress;
extern f32 gEarthWalkerAnimAdvanceRate;
extern int gEarthWalkerMoveBlendData;
extern f32 gEarthWalkerLookAtMaxDistance;
extern f32 lbl_803E6CE0;

int earthwalker_getExtraSize(void);
int earthwalker_getObjectTypeId(void);
void earthwalker_free(void);
void earthwalker_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void earthwalker_hitDetect(GameObject* obj);
void earthwalker_release(void);
void earthwalker_initialise(void);
void earthwalker_update(int obj);
int earthwalker_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int shouldAdvanceMove);
void earthwalker_init(GameObject* obj, int setup);

int dll_28B_substateHandler0(void);
int dll_28B_stateHandler0(void);
int dll_28B_substateHandler3(int obj, int ai);
int dll_28B_substateHandler2(int obj, int ai);
int dll_28B_substateHandler1(int obj, int ai);
int dll_28B_stateHandler3(GameObject* obj, int ai);
int dll_28B_stateHandler2(GameObject* obj, int ai);
int dll_28B_stateHandler1(int obj, int ai);

#endif
