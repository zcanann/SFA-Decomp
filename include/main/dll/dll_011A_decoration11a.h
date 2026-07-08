#ifndef MAIN_DLL_DLL_011A_DECORATION11A_H_
#define MAIN_DLL_DLL_011A_DECORATION11A_H_

#include "types.h"

int decoration11a_getExtraSize(void);
void decoration11a_free(void);
void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void decoration11a_hitDetect(int obj);
void decoration11a_update(void);
void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut);
void decoration11a_init(int* obj, u8* def);

#endif /* MAIN_DLL_DLL_011A_DECORATION11A_H_ */
