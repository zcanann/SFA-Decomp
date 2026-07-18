#ifndef MAIN_MAP_TEXSCROLL_H_
#define MAIN_MAP_TEXSCROLL_H_

#include "types.h"

void mapTextureScrollSetStep(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                             int secondaryXStep, int secondaryYStep, int texWidthFixed2, int texHeightFixed2);
int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                            int secondaryXStep, int secondaryYStep, int texWidthFixed2, int texHeightFixed2);

#endif /* MAIN_MAP_TEXSCROLL_H_ */
