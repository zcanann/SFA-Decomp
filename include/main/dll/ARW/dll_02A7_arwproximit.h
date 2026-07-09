#ifndef MAIN_DLL_ARW_DLL_02A7_ARWPROXIMIT_H_
#define MAIN_DLL_ARW_DLL_02A7_ARWPROXIMIT_H_

#include "global.h"

typedef struct ARWProximitSetup
{
    u8 pad00[0x31];
    u8 textVariant;
} ARWProximitSetup;

typedef struct ARWProximitState
{
    s16 spinSpeed;
    u8 pad02[2];
    void* light;
    u8 pad08[4];
    f32 warningTimer;
    f32 despawnTimer;
    u8 phase;
    u8 textVariant;
    u8 pad16[2];
} ARWProximitState;

STATIC_ASSERT(sizeof(ARWProximitState) == 0x18);
STATIC_ASSERT(offsetof(ARWProximitState, spinSpeed) == 0x00);
STATIC_ASSERT(offsetof(ARWProximitState, light) == 0x04);
STATIC_ASSERT(offsetof(ARWProximitState, warningTimer) == 0x0c);
STATIC_ASSERT(offsetof(ARWProximitState, despawnTimer) == 0x10);
STATIC_ASSERT(offsetof(ARWProximitState, phase) == 0x14);
STATIC_ASSERT(offsetof(ARWProximitState, textVariant) == 0x15);
STATIC_ASSERT(offsetof(ARWProximitSetup, textVariant) == 0x31);

int arwproximit_getExtraSize(void);
int arwproximit_getObjectTypeId(void);
void arwproximit_free(struct GameObject* obj);
void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwproximit_hitDetect(void);
void arwproximit_update(int obj);
void arwproximit_init(int obj, int setup, int p3);
void arwproximit_release(void);
void arwproximit_initialise(void);

#endif /* MAIN_DLL_ARW_DLL_02A7_ARWPROXIMIT_H_ */
