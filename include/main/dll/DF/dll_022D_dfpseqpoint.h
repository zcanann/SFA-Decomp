#ifndef MAIN_DLL_DF_DLL_022D_DFPSEQPOINT_H_
#define MAIN_DLL_DF_DLL_022D_DFPSEQPOINT_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

int DFP_seqpoint_getExtraSize(void);
int DFP_seqpoint_getObjectTypeId(void);
void DFP_seqpoint_free(void);
void DFP_seqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void DFP_seqpoint_hitDetect(void);
void DFP_seqpoint_update(GameObject* obj);
void DFP_seqpoint_init(int* obj, u8* init);
int DFP_seqpoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void DFP_seqpoint_release(void);
void DFP_seqpoint_initialise(void);

#endif /* MAIN_DLL_DF_DLL_022D_DFPSEQPOINT_H_ */
