#ifndef MAIN_DLL_SC_SCTOTEMPUZZLE_H_
#define MAIN_DLL_SC_SCTOTEMPUZZLE_H_

#include "main/dll/SC/sctotembond.h"

u8 sc_totempuzzle_checkSolvedSequence(ScTotemPuzzleObject *obj, ScTotemPuzzleState *state);
int sc_totempuzzle_getExtraSize(void);
int sc_totempuzzle_getObjectTypeId(void);
void sc_totempuzzle_free(void);
void sc_totempuzzle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_totempuzzle_hitDetect(void);

#endif /* MAIN_DLL_SC_SCTOTEMPUZZLE_H_ */
