#ifndef MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_
#define MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_

#include "main/objanim_update.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objprint_sound_api.h"

typedef struct CfPrisonUncleState
{
    GameObject* companion; /* class-0x3D object carrying the uncle's escape path */
    u8 headTrackState[0x30];
    ObjSoundState soundState;
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 released; /* GameBit 0x4D latch: his cage has been opened */
    s8 magicGranted; /* one-shot thank-you magic in CFPrisonUncle_SeqFn */
    u8 pad75[0x33];
} CfPrisonUncleState;

STATIC_ASSERT(offsetof(CfPrisonUncleState, companion) == 0x0);
STATIC_ASSERT(offsetof(CfPrisonUncleState, headTrackState) == 0x4);
STATIC_ASSERT(offsetof(CfPrisonUncleState, soundState) == 0x34);
STATIC_ASSERT(offsetof(CfPrisonUncleState, unk64) == 0x64);
STATIC_ASSERT(offsetof(CfPrisonUncleState, unk68) == 0x68);
STATIC_ASSERT(offsetof(CfPrisonUncleState, unk70) == 0x70);
STATIC_ASSERT(offsetof(CfPrisonUncleState, released) == 0x73);
STATIC_ASSERT(offsetof(CfPrisonUncleState, magicGranted) == 0x74);
STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

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

extern ObjectDescriptor gCFPrisonUncleObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_ */
