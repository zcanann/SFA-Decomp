#ifndef MAIN_DLL_DLL_010E_DEATHSEQ_H_
#define MAIN_DLL_DLL_010E_DEATHSEQ_H_

#include "global.h"

typedef struct
{
    f32 timer;                // 0x0
    f32 camX;                 // 0x4
    f32 camY;                 // 0x8
    f32 camZ;                 // 0xc
    f32 dist;                 // 0x10
    f32 distTarget;           // 0x14
    int camRotY;              // 0x18
    int camRotX;              // 0x1c
    u8 menuShown : 1;         // 0x20 bit 7
    u8 camActive : 1;         // bit 6
    u8 transitionStarted : 1; // bit 5
} DeathSeqState;

int DeathSeq_getExtraSize(void);
int DeathSeq_getObjectTypeId(void);
void DeathSeq_free(int* obj);
void DeathSeq_render(void);
void DeathSeq_hitDetect(void);
void DeathSeq_update(int* obj);
void DeathSeq_init(int* obj);
void DeathSeq_release(void);
void DeathSeq_initialise(void);

#endif /* MAIN_DLL_DLL_010E_DEATHSEQ_H_ */
