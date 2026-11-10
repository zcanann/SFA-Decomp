#ifndef DLLS_OBJECTS_438_SC_LEVELCON_H_
#define DLLS_OBJECTS_438_SC_LEVELCON_H_

#include "dlls/object_descriptor.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "game/objects/object_fwd.h"
#include "main/objseq.h"

#define SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1 0x7D
#define SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2 0x7E
#define SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3 0x7F

typedef struct ScLevelControlStatusFlags {
    u8 challengeGateGroupEnabled : 1;
    u8 unknownLowBits : 7;
} ScLevelControlStatusFlags;

typedef struct ScLevelControlState {
    f32 fogNear;
    f32 fogNearTarget;
    f32 fogNearStep;
    f32 helpTextTimer;
    f32 exitTimer;
    f32 fadeTimer;
    GameBitLatchState musicLatches;
    u8 totemComboIndex;
    u8 animEventState;
    u8 playerMapId;
    u8 animEventFlags;
    u8 musicTriggerId;
    s8 ambientMusicTriggerId;
    ScLevelControlStatusFlags statusFlags;
    u8 unknown23;
} ScLevelControlState;

STATIC_ASSERT(sizeof(ScLevelControlStatusFlags) == 0x01);

STATIC_ASSERT(offsetof(ScLevelControlState, fogNear) == 0x00);
STATIC_ASSERT(offsetof(ScLevelControlState, fogNearTarget) == 0x04);
STATIC_ASSERT(offsetof(ScLevelControlState, fogNearStep) == 0x08);
STATIC_ASSERT(offsetof(ScLevelControlState, helpTextTimer) == 0x0C);
STATIC_ASSERT(offsetof(ScLevelControlState, exitTimer) == 0x10);
STATIC_ASSERT(offsetof(ScLevelControlState, fadeTimer) == 0x14);
STATIC_ASSERT(offsetof(ScLevelControlState, musicLatches) == 0x18);
STATIC_ASSERT(offsetof(ScLevelControlState, totemComboIndex) == 0x1C);
STATIC_ASSERT(offsetof(ScLevelControlState, animEventState) == 0x1D);
STATIC_ASSERT(offsetof(ScLevelControlState, playerMapId) == 0x1E);
STATIC_ASSERT(offsetof(ScLevelControlState, animEventFlags) == 0x1F);
STATIC_ASSERT(offsetof(ScLevelControlState, musicTriggerId) == 0x20);
STATIC_ASSERT(offsetof(ScLevelControlState, ambientMusicTriggerId) == 0x21);
STATIC_ASSERT(offsetof(ScLevelControlState, statusFlags) == 0x22);
STATIC_ASSERT(offsetof(ScLevelControlState, unknown23) == 0x23);
STATIC_ASSERT(sizeof(ScLevelControlState) == 0x24);

int sc_levelcontrol_processAnimEventsCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
u8 sc_levelcontrol_getAnimEventState(GameObject* obj);
void sc_levelcontrol_applyAnimEventState(GameObject* obj, u8 animEventState);
int sc_levelcontrol_getExtraSize(void);
int sc_levelcontrol_getObjectTypeId(void);
void sc_levelcontrol_free(GameObject* obj);
void sc_levelcontrol_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void sc_levelcontrol_hitDetect(void);
void sc_levelcontrol_update(GameObject* obj);
void sc_levelcontrol_init(GameObject* obj);
void sc_levelcontrol_release(void);
void sc_levelcontrol_initialise(void);

extern u16 gScLevelControlTotemComboSequence[4];
extern ObjectDescriptor12 gSC_levelcontrolObjDescriptor;

#endif /* DLLS_OBJECTS_438_SC_LEVELCON_H_ */
