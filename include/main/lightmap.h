#ifndef MAIN_LIGHTMAP_H_
#define MAIN_LIGHTMAP_H_

#include "types.h"

u32 shouldDrawClouds(void);
void _textSetColor(int unused, int a, int b, int c, int d);
void updateEnvironment(int mode);
u32 getDrawDistanceFlag_8005cd48(void);
u32 shouldDrawShadows(void);

#endif /* MAIN_LIGHTMAP_H_ */
