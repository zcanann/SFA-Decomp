#ifndef DLLS_OBJECTS_328_CFGUARDIAN_H_
#define DLLS_OBJECTS_328_CFGUARDIAN_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "main/objprint_character_api.h"
#include "game/objects/object_setup.h"
#include "main/dll/curve_walker.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/objprint_sound_api.h"

typedef struct RomCurveDef RomCurveDef;

#define CFGUARDIAN_LINKED_OBJECT_COUNT 6

typedef struct CfGuardianPlacement {
    ObjPlacement base;
    s8 initialYaw;
    s8 variant;
} CfGuardianPlacement;

/*
 * cfguardian_getExtraSize proves the complete allocation. The anonymous
 * overlay names only fields this TU accesses outside the embedded MoveLib
 * contract.
 */
typedef struct CfGuardianState {
    MoveLibState moveLib;
    ObjSoundState soundState;
    CharacterEyeAnimState eyeAnimState;
    u8 pad67C[0x10];
    GameObject* linkedObjects[CFGUARDIAN_LINKED_OBJECT_COUNT];
    u8 pad6A4[0x18];
    RomCurveWalker path;
    u8 pad7C4[0x38];
    f32 moveSpeed;
    u8 pad800[0x25E];
    u8 bounceLatch;
    u8 padA5F[0x09];
    MoveLibTarget home;
    u8 questState;
    u8 padA81[0x0F];
    int unknownA90;
    int landingPhase;
    u8 chatterState;
    s8 chatterAlt;
    s8 chatterPick;
    u8 stateFlags;
} CfGuardianState;

STATIC_ASSERT(offsetof(CfGuardianPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(CfGuardianPlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(CfGuardianPlacement, variant) == 0x19);

STATIC_ASSERT(offsetof(CfGuardianState, moveLib) == 0x000);
STATIC_ASSERT(offsetof(CfGuardianState, moveLib.modeBits) == 0x611);
STATIC_ASSERT(offsetof(CfGuardianState, soundState) == 0x624);
STATIC_ASSERT(offsetof(CfGuardianState, eyeAnimState) == 0x654);
STATIC_ASSERT(offsetof(CfGuardianState, linkedObjects) == 0x68C);
STATIC_ASSERT(offsetof(CfGuardianState, path) == 0x6BC);
STATIC_ASSERT(offsetof(CfGuardianState, moveSpeed) == 0x7FC);
STATIC_ASSERT(offsetof(CfGuardianState, bounceLatch) == 0xA5E);
STATIC_ASSERT(offsetof(CfGuardianState, home) == 0xA68);
STATIC_ASSERT(offsetof(CfGuardianState, home.x) == 0xA74);
STATIC_ASSERT(offsetof(CfGuardianState, questState) == 0xA80);
STATIC_ASSERT(offsetof(CfGuardianState, unknownA90) == 0xA90);
STATIC_ASSERT(offsetof(CfGuardianState, landingPhase) == 0xA94);
STATIC_ASSERT(offsetof(CfGuardianState, chatterState) == 0xA98);
STATIC_ASSERT(offsetof(CfGuardianState, stateFlags) == 0xA9B);
STATIC_ASSERT(sizeof(CfGuardianState) == 0xA9C);

int cfguardian_playEventSfx(GameObject* obj, ObjAnimEventList* eventList, s16* sfxIds);
int cfguardian_isNotPathFlying(GameObject* obj);
int cfguardian_flyAlongPath(GameObject* obj, RomCurveWalker* walker, f32 speed, int pointId, f32* outPhase);
int cfguardian_steerToward(GameObject* obj, MoveLibTarget* target, f32 speed, f32* outPhase);
RomCurveDef* cfguardian_findRomCurvePointNearObject(GameObject* obj, int curveGroup, f32* outPosition, int mode);
int cfguardian_updateMain(GameObject* obj);
int cfguardian_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
int cfguardian_getExtraSize(void);
int cfguardian_getObjectTypeId(void);
void cfguardian_free(GameObject* obj, int keep);
void cfguardian_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void cfguardian_hitDetect(GameObject* obj);
void cfguardian_update(GameObject* obj);
void cfguardian_init(GameObject* obj, CfGuardianPlacement* placement);
void cfguardian_release(void);
void cfguardian_initialise(void);

extern ObjectDescriptor11ExtraSize gCFGuardianObjDescriptor;

#endif /* DLLS_OBJECTS_328_CFGUARDIAN_H_ */
