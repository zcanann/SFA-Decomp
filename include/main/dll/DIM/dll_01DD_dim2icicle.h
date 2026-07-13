#ifndef MAIN_DLL_DIM_DLL_01DD_DIM2ICICLE_H_
#define MAIN_DLL_DIM_DLL_01DD_DIM2ICICLE_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/curve.h"

extern ObjectDescriptor gDIM2IcicleObjDescriptor;

int dim2icicle_getExtraSize(void);
int dim2icicle_getObjectTypeId(void);
void dim2icicle_free(void);
void dim2icicle_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icicle_hitDetect(void);
void dim2icicle_update(GameObject* obj);
void dim2icicle_init(GameObject* obj, s8* p);
void dim2icicle_release(void);
void dim2icicle_initialise(void);

typedef struct Dim2IcicleState
{
    f32 dropY;
    s16 wobbleRotY;
    u8 mode;
    u8 dropTargetFound;
    s16 timer;
    u8 padA[2];
} Dim2IcicleState;

STATIC_ASSERT(sizeof(Dim2IcicleState) == 0xC);

#endif /* MAIN_DLL_DIM_DLL_01DD_DIM2ICICLE_H_ */
