#ifndef MAIN_DLL_DLL_02B6_CNTHITOBJEC_H
#define MAIN_DLL_DLL_02B6_CNTHITOBJEC_H

#include "main/dll/cnthitobjec_state.h"
#include "main/game_object.h"

extern int lbl_8032BEF8[];
extern u8 lbl_803DC42C;
extern int lbl_803DC428;

int cnthitobjec_getExtraSize(void);
int cnthitobjec_getObjectTypeId(void);
void cnthitobjec_free(void);
void cnthitobjec_release(void);
void cnthitobjec_initialise(void);
void cnthitobjec_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
int cnthitobjec_SeqFn(int obj, int p2, int p3);
void cnthitobjec_hitDetect(GameObject* obj);
void cnthitobjec_init(GameObject* obj, int setup);
void cnthitobjec_update(GameObject* obj);
int mcupgrade_SeqFn(GameObject* obj, int unused, CntHitObjectAnimEvent* event);

#endif
