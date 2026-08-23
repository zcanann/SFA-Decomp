#ifndef DLLS_OBJECTS_399_ECSH_SHRINE_H_
#define DLLS_OBJECTS_399_ECSH_SHRINE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/model_light.h"
#include "main/objseq.h"

#define ECSH_SHRINE_OBJECT_GROUP 0xB

typedef struct ECSHShrineState {
    ModelLightStruct* light;
    f32 animTimer;
    f32 cooldownTimer;
    f32 guessTimer;
    f32 voiceTimer;
    f32 shuffleSfxThreshold;
    s16 unknown18;
    s16 unknown1A;
    s16 unknown1C;
    s16 unknown1E;
    s16 unknown20;
    s16 shuffleCount;
    s16 animState;
    s16 matchFlag;
    s16 orbitPhaseA;
    s16 orbitPhaseB;
    s16 orbitPhaseC;
    u8 spiritCup;
    u8 testPhase;
    u8 transitionReady;
    u8 shuffleSfxPlayed;
    u8 introTextLatch;
    u8 unknown33;
    GameBitLatchState gameBitLatch;
} ECSHShrineState;

STATIC_ASSERT(offsetof(ECSHShrineState, light) == 0x00);
STATIC_ASSERT(offsetof(ECSHShrineState, animTimer) == 0x04);
STATIC_ASSERT(offsetof(ECSHShrineState, cooldownTimer) == 0x08);
STATIC_ASSERT(offsetof(ECSHShrineState, guessTimer) == 0x0C);
STATIC_ASSERT(offsetof(ECSHShrineState, voiceTimer) == 0x10);
STATIC_ASSERT(offsetof(ECSHShrineState, shuffleSfxThreshold) == 0x14);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown18) == 0x18);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown1A) == 0x1A);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown1C) == 0x1C);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown20) == 0x20);
STATIC_ASSERT(offsetof(ECSHShrineState, shuffleCount) == 0x22);
STATIC_ASSERT(offsetof(ECSHShrineState, animState) == 0x24);
STATIC_ASSERT(offsetof(ECSHShrineState, matchFlag) == 0x26);
STATIC_ASSERT(offsetof(ECSHShrineState, orbitPhaseA) == 0x28);
STATIC_ASSERT(offsetof(ECSHShrineState, orbitPhaseB) == 0x2A);
STATIC_ASSERT(offsetof(ECSHShrineState, orbitPhaseC) == 0x2C);
STATIC_ASSERT(offsetof(ECSHShrineState, spiritCup) == 0x2E);
STATIC_ASSERT(offsetof(ECSHShrineState, testPhase) == 0x2F);
STATIC_ASSERT(offsetof(ECSHShrineState, transitionReady) == 0x30);
STATIC_ASSERT(offsetof(ECSHShrineState, shuffleSfxPlayed) == 0x31);
STATIC_ASSERT(offsetof(ECSHShrineState, introTextLatch) == 0x32);
STATIC_ASSERT(offsetof(ECSHShrineState, unknown33) == 0x33);
STATIC_ASSERT(offsetof(ECSHShrineState, gameBitLatch) == 0x34);
STATIC_ASSERT(sizeof(ECSHShrineState) == 0x38);

extern ObjectDescriptor15 gECSHShrineObjDescriptor;

void ecshShrine_updateHoverMotion(GameObject* obj);
int ecshShrine_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate);
void ecshShrine_checkCupPick(u8 cupIndex);
void ecshShrine_setCupPosition(u8 cupIndex, f32 x, f32 z);
void ecshShrine_getPhaseAndSpiritCup(int* outAnimState, u8* outSpiritCup);
void ecshShrine_getCupPosition(u8 cupIndex, f32* outX, f32* outZ);
void ecshShrine_func0A(s16* out);
int ecshShrine_getExtraSize(void);
int ecshShrine_getObjectTypeId(void);
void ecshShrine_free(GameObject* obj);
void ecshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void ecshShrine_hitDetect(void);
void ecshShrine_update(GameObject* obj);
void ecshShrine_init(GameObject* obj, const s8* placement);
void ecshShrine_release(void);
void ecshShrine_initialise(void);

#endif /* DLLS_OBJECTS_399_ECSH_SHRINE_H_ */
