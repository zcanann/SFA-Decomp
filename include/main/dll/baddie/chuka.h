#ifndef MAIN_DLL_BADDIE_CHUKA_H_
#define MAIN_DLL_BADDIE_CHUKA_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "global.h"

typedef struct ChukaState
{
    f32 startY;
    int linkedObject; /* 0x04: the 0x431-type object driving the mode */
    u8 modeIndex;     /* 0x08: index into gChukaModeTable */
    u8 mode;          /* 0x09 */
    u8 pad0A[2];
} ChukaState;

STATIC_ASSERT(offsetof(ChukaState, linkedObject) == 0x4);
STATIC_ASSERT(sizeof(ChukaState) == 0xC);

void chuka_init(GameObject* obj, int params);
int chuka_SeqFn(void);
void DFP_Floorbar_free(int* obj);
void chuka_release(void);
void chuka_initialise(void);
int DFP_Floorbar_getObjectTypeId(void);
int DFP_Floorbar_getExtraSize(void);
void DFP_Floorbar_render(int p1, int p2, int p3, int p4, int p5, s8 p6);
void DFP_Floorbar_hitDetect(int* obj);
int dfpfloorbar_SeqFn(void);

#endif /* MAIN_DLL_BADDIE_CHUKA_H_ */
