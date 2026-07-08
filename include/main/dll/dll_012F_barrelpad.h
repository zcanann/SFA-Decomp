#ifndef MAIN_DLL_DLL_012F_BARRELPAD_H_
#define MAIN_DLL_DLL_012F_BARRELPAD_H_

#include "global.h"

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

int BarrelPad_getExtraSize(void);
int BarrelPad_getObjectTypeId(void);
void BarrelPad_free(void);
void BarrelPad_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void BarrelPad_hitDetect(void);
void BarrelPad_update(s16* obj);
void BarrelPad_init(s16* obj, u8* def);
void BarrelPad_release(void);
void BarrelPad_initialise(void);

#endif /* MAIN_DLL_DLL_012F_BARRELPAD_H_ */
