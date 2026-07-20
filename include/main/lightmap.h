#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "main/lightmap_api.h"

void updateEnvironment(int mode);
int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage);
void fn_8005D0BC(int unused, u8 red, u8 green, u8 blue, int d);
void sceneRender(int a, int b, int c, int d, int e, int f);

#endif /* MAIN_LIGHTMAP_H_ */
