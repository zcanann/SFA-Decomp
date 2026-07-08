#ifndef MAIN_DLL_DLL_015F_ATTRACTOR_H_
#define MAIN_DLL_DLL_015F_ATTRACTOR_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct AttractorMapData
{
    ObjPlacement base;
    s8 setupByte; /* 0x18: -> anim.rotX << 8 */
    s8 mode;      /* 0x19 */
    s16 scale;    /* 0x1a */
} AttractorMapData;

STATIC_ASSERT(offsetof(AttractorMapData, setupByte) == 0x18);
STATIC_ASSERT(offsetof(AttractorMapData, mode) == 0x19);
STATIC_ASSERT(offsetof(AttractorMapData, scale) == 0x1a);

void attractor_getTarget(GameObject* obj, void** out);
int attractor_setScale(int* obj);
int attractor_getExtraSize(void);
int attractor_getObjectTypeId(void);
void attractor_free(int obj);
void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void attractor_hitDetect(void);
void attractor_update(void);
void attractor_init(GameObject* obj, AttractorMapData* data);
void attractor_release(void);
void attractor_initialise(void);

#endif /* MAIN_DLL_DLL_015F_ATTRACTOR_H_ */
