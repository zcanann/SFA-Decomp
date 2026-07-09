#ifndef MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_
#define MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_

#include "global.h"

typedef struct DrmusiccontState
{
    u8 pad0[0x4 - 0x0];
    f32 stingerTimer; /* 0x04 */
} DrmusiccontState;

int drmusiccont_getExtraSize(void);
int drmusiccont_getObjectTypeId(void);
void drmusiccont_free(int obj);
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void drmusiccont_hitDetect(void);
void drmusiccont_release(void);
void drmusiccont_initialise(void);
void drmusiccont_init(struct GameObject* obj);
void drmusiccont_update(int obj);

#endif /* MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_ */
