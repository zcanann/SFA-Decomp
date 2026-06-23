#ifndef MAIN_DLL_MMSHRINE_ECSH_SHRINE_H_
#define MAIN_DLL_MMSHRINE_ECSH_SHRINE_H_

#include "global.h"
#include "main/dll/mmshrineanimobj_struct.h"

/* Floating shrine model behaviour (DLL 0x18F). */
void ecsh_shrine_updateMotion(MmShrineAnimObj* obj);
int ecsh_shrine_SeqFn(void* obj, int unused, void* eventList);

/* Puzzle helpers reached through the gEcShShrineActiveObject singleton; called
 * by the cup objects (DLL 0x190) to read/write the shell-game working set. */
void ecsh_shrine_getPhaseAndSpiritCup(int* outAnimState, u8* outSpiritCup);
void ecsh_shrine_checkCupPick(u8 cupIndex);
void ecsh_shrine_setCupPos(u8 cupIndex, f32 x, f32 z);
void ecsh_shrine_getCupPos(u8 cupIndex, f32* outX, f32* outZ);
void ecsh_shrine_setScale(s16* out);

/* Object-descriptor entry points. */
int ecsh_shrine_getExtraSize(void);
int ecsh_shrine_getObjectTypeId(void);
void ecsh_shrine_free(int* obj);
void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void ecsh_shrine_hitDetect(void);
void ecsh_shrine_update(s16* obj);
void ecsh_shrine_init(s16* obj, s8* def);
void ecsh_shrine_release(void);
void ecsh_shrine_initialise(void);

#endif /* MAIN_DLL_MMSHRINE_ECSH_SHRINE_H_ */
