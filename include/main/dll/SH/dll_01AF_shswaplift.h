#ifndef MAIN_DLL_SH_DLL_01AF_SHSWAPLIFT_H_
#define MAIN_DLL_SH_DLL_01AF_SHSWAPLIFT_H_

#include "main/game_object.h"
#include "types.h"

int warpstonelift_getExtraSize(void);
int warpstonelift_getObjectTypeId(void);
void warpstonelift_free(void);
void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void warpstonelift_hitDetect(void);
void warpstonelift_update(GameObject* obj);
void warpstonelift_init(GameObject* obj, s8* def);
void warpstonelift_release(void);
void warpstonelift_initialise(void);

#endif /* MAIN_DLL_SH_DLL_01AF_SHSWAPLIFT_H_ */
