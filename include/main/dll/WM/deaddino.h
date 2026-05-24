#ifndef MAIN_DLL_WM_DEADDINO_H_
#define MAIN_DLL_WM_DEADDINO_H_

#include "ghidra_import.h"

typedef struct SCTotemPuzzleObject SCTotemPuzzleObject;
typedef struct SCTotemPuzzleState SCTotemPuzzleState;

int fn_801DD1A8(SCTotemPuzzleObject *obj, SCTotemPuzzleState *state);
int sc_totempuzzle_getExtraSize(void);
int sc_totempuzzle_getObjectTypeId(void);
void sc_totempuzzle_free(void);
void sc_totempuzzle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_totempuzzle_hitDetect(void);

#endif /* MAIN_DLL_WM_DEADDINO_H_ */
