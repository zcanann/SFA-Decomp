#ifndef MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_
#define MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_

#include "main/objanim_update.h"
#include "main/game_object.h"

typedef struct CfPrisonUncleState
{
    GameObject* target; /* class-0x3D companion object (carries his escape path) */
    u8 lookBlock[0x30]; /* fn_8003ADC4 head-track block */
    u8 audioBlock[0x30]; /* objAudioFn block */
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 released; /* GameBit 0x4D latch: his cage has been opened */
    s8 magicGranted; /* one-shot thank-you magic in CFPrisonUncle_SeqFn */
    u8 pad75[0x33];
} CfPrisonUncleState;

int CFPrisonUncle_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int cfprisonuncle_getExtraSize(void);
int cfprisonuncle_getObjectTypeId(void);
void cfprisonuncle_free(void);
void cfprisonuncle_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfprisonuncle_hitDetect(void);
void cfprisonuncle_update(GameObject* obj);
void cfprisonuncle_init(GameObject* obj);
void cfprisonuncle_release(void);
void cfprisonuncle_initialise(void);

#endif /* MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_ */
