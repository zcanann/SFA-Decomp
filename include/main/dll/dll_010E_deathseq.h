#ifndef MAIN_DLL_DLL_010E_DEATHSEQ_H_
#define MAIN_DLL_DLL_010E_DEATHSEQ_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct DeathSeqState
{
    f32 timer;                // 0x0
    f32 savedCamX;            // 0x4
    f32 savedCamY;            // 0x8
    f32 savedCamZ;            // 0xc
    f32 cameraDistance;       // 0x10
    f32 cameraDistanceTarget; // 0x14
    int savedYaw;             // 0x18: sign-extended CameraViewSlot yaw
    int savedPitch;           // 0x1c: sign-extended CameraViewSlot pitch
    u8 menuShown : 1;         // 0x20 bit 7
    u8 camActive : 1;         // bit 6
    u8 transitionStarted : 1; // bit 5
    u8 pad21[3];
} DeathSeqState;

STATIC_ASSERT(offsetof(DeathSeqState, savedCamX) == 0x4);
STATIC_ASSERT(offsetof(DeathSeqState, cameraDistance) == 0x10);
STATIC_ASSERT(offsetof(DeathSeqState, savedYaw) == 0x18);
STATIC_ASSERT(sizeof(DeathSeqState) == 0x24);

int DeathSeq_getExtraSize(void);
int DeathSeq_getObjectTypeId(void);
void DeathSeq_free(GameObject* obj);
void DeathSeq_render(void);
void DeathSeq_hitDetect(void);
void DeathSeq_update(GameObject* obj);
void DeathSeq_init(GameObject* obj);
void DeathSeq_release(void);
void DeathSeq_initialise(void);

extern ObjectDescriptor gDeathSeqObjDescriptor;

#endif /* MAIN_DLL_DLL_010E_DEATHSEQ_H_ */
