#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "main/lightmap_api.h"

void _textSetColor(int unused, int a, int b, int c, int d);
void updateEnvironment(int mode);
int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage);

#endif /* MAIN_LIGHTMAP_H_ */
