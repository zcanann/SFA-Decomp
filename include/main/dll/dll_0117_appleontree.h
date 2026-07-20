#ifndef MAIN_DLL_CRACKANIM_H_
#define MAIN_DLL_CRACKANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct AppleOnTreeState
{
    u32 unk00;
    f32 phaseDuration;
    f32 elapsedTime;
    f32 flightTime;
    f32 stageEnd0; /* 0x10: elapsed-fraction at which GROWING -> RIPE */
    f32 stageEnd1; /* 0x14: RIPE -> FALLING */
    f32 stageEnd2; /* 0x18: FALLING -> LANDED */
    f32 stageEnd3; /* 0x1C: LANDED -> auto knock-loose */
    f32 fadeThreshold;
    f32 fallScale;
    f32 velY;
    f32 posY;
    f32 dropHeight;
    f32 splashPosY;
    u16 healthRestore;
    u8 animState;
    u8 pad3B;
    f32 extraAccel;
    f32 gravity;
    f32 bounceVel;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad4E[2];
    f32 totalFlightTime;
    f32 fallBlendDivisor; /* 0x54 */
    u8 pad58[0x5A - 0x58];
    u8 flags;
    u8 pad5B;
    s16 triggerGameBit; /* 0x5C: head of the ObjMsg 0x7000a grab-trigger descriptor
                           (&triggerGameBit passed as the msg param). The player's
                           0x7000a handler reads *param as this gamebit id: bit>0 ->
                           mainGetBit(bit) gates + mainSetBits(bit,1), else the no-bit
                           grab path; -1 = no gamebit (player.c). */
    s16 pickupMsgValue; /* 0x5E: payload word of the grab-trigger descriptor; the
                           player's 0x7000a handler copies *(param+2) into its
                           interaction slot (matches collectible/ediblemushroom). */
    f32 unk60;
} AppleOnTreeState;

extern ObjectDescriptor gDllFCObjDescriptor;

void AppleOnTree_update(int param_1);
void AppleOnTree_init(int obj, int def);
int AppleOnTree_getExtraSize(void);
void AppleOnTree_setScale(void);


/* extern-cleanup: defining-file public prototypes */
void AppleOnTree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void AppleOnTree_free(int* obj);
u8 AppleOnTree_modelMtxFn(int* obj);

#endif /* MAIN_DLL_CRACKANIM_H_ */
