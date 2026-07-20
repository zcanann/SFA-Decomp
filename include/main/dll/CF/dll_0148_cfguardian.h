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
#include "main/objprint_sound_api.h"
#include "main/dll/dll_002E_moveLib.h"

typedef struct CfGuardianState {
    union {
        MoveLibState moveLib;
        struct {
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
        };
    };
    ObjSoundState soundState; /* 0x624 */
    u8 eyeBlock[0x38];    /* 0x654: characterDoEyeAnims block */
    int linkedObjs[6];    /* 0x68c: freed with the guardian */
    u8 pad6A4[0x18];
    RomCurveWalker path;  /* 0x6bc: curve walker used by cfguardianFlyAlongPath */
    u8 pathPad[0x38];
    f32 moveSpeed;        /* 0x7fc */
    u8 pad800[0x25e];
    u8 bounceLatch;            /* bounce-velocity latch while landing */
    u8 padA5F[9];
    MoveLibTarget home;   /* 0xa68: steer target filled from a rom-curve point */
    u8 questState;        /* 0xa80: 16-state quest progression */
    u8 padA81[0xf];
    int unkA90;
    int landingPhase;     /* 0xa94 */
    u8 chatterState;      /* 0xa98: 1 ready, 2 playing */
    s8 chatterAlt;
    s8 chatterPick;
    u8 flagsA9B;          /* 1 move-latched, 2 path-flying, 4 homing */
} CfGuardianState;

STATIC_ASSERT(offsetof(CfGuardianState, soundState) == 0x624);
STATIC_ASSERT(offsetof(CfGuardianState, eyeBlock) == 0x654);
STATIC_ASSERT(offsetof(CfGuardianState, linkedObjs) == 0x68c);
STATIC_ASSERT(offsetof(CfGuardianState, path) == 0x6bc);
STATIC_ASSERT(offsetof(CfGuardianState, moveSpeed) == 0x7fc);
STATIC_ASSERT(offsetof(CfGuardianState, home) == 0xa68);
STATIC_ASSERT(offsetof(CfGuardianState, home.x) == 0xa74);
STATIC_ASSERT(offsetof(CfGuardianState, questState) == 0xa80);
STATIC_ASSERT(offsetof(CfGuardianState, landingPhase) == 0xa94);
STATIC_ASSERT(offsetof(CfGuardianState, flagsA9B) == 0xa9b);
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

int* findRomCurvePointNearObject(GameObject* obj, int p2, int* outVec, int p4);
int cfguardianFlyAlongPath(GameObject* obj, RomCurveWalker* walker, f32 speed, int pointId, f32* outPhase);
int cfguardianSteerToward(GameObject* obj, MoveLibTarget* target, f32 speed, f32* outPhase);
int cfguardian_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int cfguardian_setScale(GameObject* obj);
int cfguardian_getExtraSize(void);
int cfguardian_getObjectTypeId(void);
void cfguardian_free(GameObject* obj, int keep);
void cfguardian_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfguardian_hitDetect(GameObject* obj);
void cfguardian_update(GameObject* obj);
void cfguardian_init(GameObject* obj, u8* params);
void cfguardian_release(void);
void cfguardian_initialise(void);

#endif /* MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_ */
