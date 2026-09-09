#ifndef MAIN_DLL_WC_DLL_028A_WCEARTHWALKER_H
#define MAIN_DLL_WC_DLL_028A_WCEARTHWALKER_H

#include "global.h"
#include "main/objprint_character_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/objHitReact.h"
#include "main/objseq.h"
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

typedef struct EarthWalkerPlacement
{
    ObjPlacement base;
    s8 spawnRot;
    u8 encounterType;
} EarthWalkerPlacement;

STATIC_ASSERT(offsetof(EarthWalkerPlacement, spawnRot) == 0x18);

typedef struct EarthWalkerState
{
    u8 pad000[0x600];
    u8 animPhase;
    u8 pad601[0x610 - 0x601];
    u8 hitTriggerId;
    u8 moveLibFlags611;
    u8 pad612[0x624 - 0x612];
    CharacterEyeAnimState eyeAnimState;
    u8 pad64C[0x8];
    f32 hitReactStepScale;
    u8 interactionState;
    u8 flags;
    u8 hitReactState;
    u8 encounterType;
    s8 lastTriggeredState;
    u8 pad65D[0x660 - 0x65D];
} EarthWalkerState;

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

extern ObjHitReactEntry gEarthWalkerHitReactEntries[];
extern f32 gEarthWalkerMoveStartProgress;
extern f32 gEarthWalkerAnimAdvanceRate;
extern int gEarthWalkerMoveBlendData;
extern f32 gEarthWalkerLookAtMaxDistance;
extern f32 gEarthWalkerRenderScale;

int earthwalker_getExtraSize(void);
int earthwalker_getObjectTypeId(void);
void earthwalker_free(void);
void earthwalker_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void earthwalker_hitDetect(GameObject* obj);
void earthwalker_release(void);
void earthwalker_initialise(void);
void earthwalker_update(GameObject* obj);
int earthwalker_SeqFn(GameObject* ewObj, int unused, ObjSeqState* animUpdate, int shouldAdvanceMove);
void earthwalker_init(GameObject* obj, EarthWalkerPlacement* setup);

struct BaddieState;

int dll_28B_substateHandler0(void);
int dll_28B_stateHandler0(void);
int dll_28B_substateHandler3(GameObject* obj, struct BaddieState* ai);
int dll_28B_substateHandler2(GameObject* obj, struct BaddieState* ai);
int dll_28B_substateHandler1(GameObject* obj, struct BaddieState* ai);
int dll_28B_stateHandler3(GameObject* obj, struct BaddieState* ai);
int dll_28B_stateHandler2(GameObject* obj, struct BaddieState* ai);
int dll_28B_stateHandler1(GameObject* obj, struct BaddieState* ai);

#endif
