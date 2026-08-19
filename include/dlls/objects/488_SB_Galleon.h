#ifndef DLLS_OBJECTS_488_SB_GALLEON_H_
#define DLLS_OBJECTS_488_SB_GALLEON_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "main/objseq.h"

/* SB_Galleon_getExtraSize() allocates this complete 0xB4-byte state. */
typedef struct SBGalleonState {
    f32 driftX;
    f32 driftY;
    f32 driftZ;
    f32 refZ;
    u8 unk10[0xC];
    f32 speed;
    s16 bobPhase;
    s16 rollLatch;
    s16 turnRate;
    s16 timer26;
    s8 cycleKind;
    s8 phase;
    s8 sweepDir;
    s8 stage;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 swayX;
    f32 swayY;
    f32 swayZ;
    f32 moveScale;
    GameObject* targetObj;
    GameObject* linkedActor;
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    f32 swayScaleSmooth;
    f32 rollScaleSmooth;
    f32 swayResponseSmooth;
    u16 shieldAngle;
    u8 unk6A[2];
    s16 fadeTimer;
    s16 phaseTimer;
    s8 cameraState;
    u8 unk71;
    s16 mapLayer;
    f32 textAlpha;
    u8 textRising;
    u8 damagePhase;
    s8 flightPattern;
    u8 unk7B;
    s8 phaseCounter;
    u8 unk7D[3];
    u8 musicLatch;
    u8 shieldSfxLatch;
    s16 headingLatch;
    u8 unk84;
    u8 sprayActive;
    u8 unk86[2];
    f32 wanderA;
    f32 wanderB;
    f32 wanderTimerA;
    f32 wanderTimerB;
    int musicIdA;
    int musicIdB;
    u8 wanderFlagA;
    u8 wanderFlagB;
    u16 envfxCycle;
    u8 envfxIndex;
    u8 envfxActs[6];
    u8 skyFlag;
    f32 textTimer;
    u8 gameBitLatch[4];
} SBGalleonState;

STATIC_ASSERT(offsetof(SBGalleonState, driftX) == 0x00);
STATIC_ASSERT(offsetof(SBGalleonState, driftY) == 0x04);
STATIC_ASSERT(offsetof(SBGalleonState, driftZ) == 0x08);
STATIC_ASSERT(offsetof(SBGalleonState, refZ) == 0x0C);
STATIC_ASSERT(offsetof(SBGalleonState, unk10) == 0x10);
STATIC_ASSERT(offsetof(SBGalleonState, speed) == 0x1C);
STATIC_ASSERT(offsetof(SBGalleonState, bobPhase) == 0x20);
STATIC_ASSERT(offsetof(SBGalleonState, rollLatch) == 0x22);
STATIC_ASSERT(offsetof(SBGalleonState, turnRate) == 0x24);
STATIC_ASSERT(offsetof(SBGalleonState, timer26) == 0x26);
STATIC_ASSERT(offsetof(SBGalleonState, cycleKind) == 0x28);
STATIC_ASSERT(offsetof(SBGalleonState, phase) == 0x29);
STATIC_ASSERT(offsetof(SBGalleonState, sweepDir) == 0x2A);
STATIC_ASSERT(offsetof(SBGalleonState, stage) == 0x2B);
STATIC_ASSERT(offsetof(SBGalleonState, posX) == 0x2C);
STATIC_ASSERT(offsetof(SBGalleonState, posY) == 0x30);
STATIC_ASSERT(offsetof(SBGalleonState, posZ) == 0x34);
STATIC_ASSERT(offsetof(SBGalleonState, swayX) == 0x38);
STATIC_ASSERT(offsetof(SBGalleonState, swayY) == 0x3C);
STATIC_ASSERT(offsetof(SBGalleonState, swayZ) == 0x40);
STATIC_ASSERT(offsetof(SBGalleonState, moveScale) == 0x44);
STATIC_ASSERT(offsetof(SBGalleonState, targetObj) == 0x48);
STATIC_ASSERT(offsetof(SBGalleonState, linkedActor) == 0x4C);
STATIC_ASSERT(offsetof(SBGalleonState, homeX) == 0x50);
STATIC_ASSERT(offsetof(SBGalleonState, homeY) == 0x54);
STATIC_ASSERT(offsetof(SBGalleonState, homeZ) == 0x58);
STATIC_ASSERT(offsetof(SBGalleonState, swayScaleSmooth) == 0x5C);
STATIC_ASSERT(offsetof(SBGalleonState, rollScaleSmooth) == 0x60);
STATIC_ASSERT(offsetof(SBGalleonState, swayResponseSmooth) == 0x64);
STATIC_ASSERT(offsetof(SBGalleonState, shieldAngle) == 0x68);
STATIC_ASSERT(offsetof(SBGalleonState, unk6A) == 0x6A);
STATIC_ASSERT(offsetof(SBGalleonState, fadeTimer) == 0x6C);
STATIC_ASSERT(offsetof(SBGalleonState, phaseTimer) == 0x6E);
STATIC_ASSERT(offsetof(SBGalleonState, cameraState) == 0x70);
STATIC_ASSERT(offsetof(SBGalleonState, unk71) == 0x71);
STATIC_ASSERT(offsetof(SBGalleonState, mapLayer) == 0x72);
STATIC_ASSERT(offsetof(SBGalleonState, textAlpha) == 0x74);
STATIC_ASSERT(offsetof(SBGalleonState, textRising) == 0x78);
STATIC_ASSERT(offsetof(SBGalleonState, damagePhase) == 0x79);
STATIC_ASSERT(offsetof(SBGalleonState, flightPattern) == 0x7A);
STATIC_ASSERT(offsetof(SBGalleonState, unk7B) == 0x7B);
STATIC_ASSERT(offsetof(SBGalleonState, phaseCounter) == 0x7C);
STATIC_ASSERT(offsetof(SBGalleonState, unk7D) == 0x7D);
STATIC_ASSERT(offsetof(SBGalleonState, musicLatch) == 0x80);
STATIC_ASSERT(offsetof(SBGalleonState, shieldSfxLatch) == 0x81);
STATIC_ASSERT(offsetof(SBGalleonState, headingLatch) == 0x82);
STATIC_ASSERT(offsetof(SBGalleonState, unk84) == 0x84);
STATIC_ASSERT(offsetof(SBGalleonState, sprayActive) == 0x85);
STATIC_ASSERT(offsetof(SBGalleonState, unk86) == 0x86);
STATIC_ASSERT(offsetof(SBGalleonState, wanderA) == 0x88);
STATIC_ASSERT(offsetof(SBGalleonState, wanderB) == 0x8C);
STATIC_ASSERT(offsetof(SBGalleonState, wanderTimerA) == 0x90);
STATIC_ASSERT(offsetof(SBGalleonState, wanderTimerB) == 0x94);
STATIC_ASSERT(offsetof(SBGalleonState, musicIdA) == 0x98);
STATIC_ASSERT(offsetof(SBGalleonState, musicIdB) == 0x9C);
STATIC_ASSERT(offsetof(SBGalleonState, wanderFlagA) == 0xA0);
STATIC_ASSERT(offsetof(SBGalleonState, wanderFlagB) == 0xA1);
STATIC_ASSERT(offsetof(SBGalleonState, envfxCycle) == 0xA2);
STATIC_ASSERT(offsetof(SBGalleonState, envfxIndex) == 0xA4);
STATIC_ASSERT(offsetof(SBGalleonState, envfxActs) == 0xA5);
STATIC_ASSERT(offsetof(SBGalleonState, skyFlag) == 0xAB);
STATIC_ASSERT(offsetof(SBGalleonState, textTimer) == 0xAC);
STATIC_ASSERT(offsetof(SBGalleonState, gameBitLatch) == 0xB0);
STATIC_ASSERT(sizeof(SBGalleonState) == 0xB4);

typedef int (*SBGalleonVtblFn)(GameObject* galleon);

/* Class-specific callbacks following the standard eight object callbacks. */
typedef struct SBGalleonVtbl {
    ObjectInterface reserved00;
    SBGalleonVtblFn onPartDestroyed;
    SBGalleonVtblFn getStage;
    SBGalleonVtblFn getPhase;
    SBGalleonVtblFn getDamagePhase;
} SBGalleonVtbl;

STATIC_ASSERT(offsetof(SBGalleonVtbl, reserved00) == 0x00);
STATIC_ASSERT(offsetof(SBGalleonVtbl, onPartDestroyed) == 0x20);
STATIC_ASSERT(offsetof(SBGalleonVtbl, getStage) == 0x24);
STATIC_ASSERT(offsetof(SBGalleonVtbl, getPhase) == 0x28);
STATIC_ASSERT(offsetof(SBGalleonVtbl, getDamagePhase) == 0x2C);
STATIC_ASSERT(sizeof(SBGalleonVtbl) == 0x30);

#define SB_GALLEON_VTBL(galleon) ((SBGalleonVtbl*)*((GameObject*)(galleon))->anim.dll)

extern ObjectDescriptor15 gSB_GalleonObjDescriptor;

void SB_Galleon_updateFlight(GameObject* obj);
void SB_Galleon_updateEnvfxGameBits(SBGalleonState* state);
int SB_Galleon_getCameraState(GameObject* obj);
void SB_Galleon_updateShield(GameObject* obj);
void SB_Galleon_onSeqFree(GameObject* obj);
void SB_Galleon_updateSkyLighting(GameObject* obj, SBGalleonState* state);
int SB_Galleon_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
GameObject* getSbGalleon(void);
int SB_Galleon_func0E(GameObject* obj);
u8 SB_Galleon_getDamagePhase(GameObject* obj);
int SB_Galleon_getPhase(GameObject* obj);
s32 SB_Galleon_getStage(GameObject* obj);
int SB_Galleon_onPartDestroyed(GameObject* obj);
int SB_Galleon_getExtraSize(void);
int SB_Galleon_getObjectTypeId(void);
void SB_Galleon_free(GameObject* obj, int leavingMap);
void SB_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_Galleon_hitDetect(GameObject* obj);
void SB_Galleon_update(GameObject* obj);
void SB_Galleon_init(GameObject* obj);
void SB_Galleon_release(void);
void SB_Galleon_initialise(void);

#endif /* DLLS_OBJECTS_488_SB_GALLEON_H_ */
