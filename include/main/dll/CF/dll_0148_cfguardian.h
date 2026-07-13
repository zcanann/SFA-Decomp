#ifndef MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_
#define MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/player_status.h"
#include "main/objseq.h"
#include "main/dll/dll_002E_moveLib.h"

typedef struct CfGuardianState {
    u8 pad0[0x2 - 0x0];
    u16 sfxId;
    s32 unk4;
    s32 unk8;
    s32 unkC;
    s32 unk10;
    s32 unk14;
    s32 unk18;
    s32 unk1C;
    s32 unk20;
    s32 unk24;
    s32 unk28;
    u8 pad2C[0x7C - 0x2C];
    f32 targetPosY;
    f32 velocityY;
    u8 pad84[0x611 - 0x84];
    u8 flags611;
    u8 pad612[0x12];
    u8 audioBlock[0x30];  /* 0x624: objAudioFn block */
    u8 eyeBlock[0x38];    /* 0x654: characterDoEyeAnims block */
    int linkedObjs[6];    /* 0x68c: freed with the guardian */
    u8 pad6A4[0x18];
    u8 pathBlock[0x140];  /* 0x6bc: cfguardianFlyAlongPath path-flight block */
    f32 moveSpeed;        /* 0x7fc */
    u8 pad800[0x25e];
    u8 bounceLatch;            /* bounce-velocity latch while landing */
    u8 padA5F[9];
    s16 homeYaw;          /* 0xa68: embedded steer-target header (cfguardianSteerToward) */
    u8 padA6A[0xa];
    f32 homeX;            /* 0xa74: nearest rom-curve point after landing */
    f32 homeY;
    f32 homeZ;
    u8 questState;        /* 0xa80: 16-state quest progression */
    u8 padA81[0xf];
    int unkA90;
    int landingPhase;     /* 0xa94 */
    u8 chatterState;      /* 0xa98: 1 ready, 2 playing */
    s8 chatterAlt;
    s8 chatterPick;
    u8 flagsA9B;          /* 1 move-latched, 2 path-flying, 4 homing */
} CfGuardianState;

STATIC_ASSERT(offsetof(CfGuardianState, audioBlock) == 0x624);
STATIC_ASSERT(offsetof(CfGuardianState, eyeBlock) == 0x654);
STATIC_ASSERT(offsetof(CfGuardianState, linkedObjs) == 0x68c);
STATIC_ASSERT(offsetof(CfGuardianState, pathBlock) == 0x6bc);
STATIC_ASSERT(offsetof(CfGuardianState, moveSpeed) == 0x7fc);
STATIC_ASSERT(offsetof(CfGuardianState, homeYaw) == 0xa68);
STATIC_ASSERT(offsetof(CfGuardianState, homeX) == 0xa74);
STATIC_ASSERT(offsetof(CfGuardianState, questState) == 0xa80);
STATIC_ASSERT(offsetof(CfGuardianState, landingPhase) == 0xa94);
STATIC_ASSERT(offsetof(CfGuardianState, flagsA9B) == 0xa9b);
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4);
int cfguardianSteerToward(int* obj, int* target, f32 speed, int p4);
int cfguardian_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int cfguardian_setScale(int* obj);
int cfguardian_getExtraSize(void);
int cfguardian_getObjectTypeId(void);
void cfguardian_free(int* obj, int keep);
void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfguardian_hitDetect(int* obj);
void cfguardian_update(GameObject* obj);
void cfguardian_init(int* obj, u8* params);
void cfguardian_release(void);
void cfguardian_initialise(void);

#endif /* MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_ */
