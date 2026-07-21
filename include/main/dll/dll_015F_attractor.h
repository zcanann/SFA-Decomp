#ifndef MAIN_DLL_DLL_015F_ATTRACTOR_H_
#define MAIN_DLL_DLL_015F_ATTRACTOR_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef enum AttractorMode
{
    ATTRACTOR_MODE_NONE = 0,
    ATTRACTOR_MODE_RETURN_SELF = 1,
    ATTRACTOR_MODE_FACE_PLAYER = 2
} AttractorMode;

typedef struct AttractorPlacement
{
    ObjPlacement base;
    s8 rotXByte;
    s8 mode; /* AttractorMode */
    s16 scale;
} AttractorPlacement;

STATIC_ASSERT(offsetof(AttractorPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(AttractorPlacement, mode) == 0x19);
STATIC_ASSERT(offsetof(AttractorPlacement, scale) == 0x1a);
STATIC_ASSERT(sizeof(AttractorPlacement) == 0x1c);

void attractor_getTarget(GameObject* obj, GameObject** outTarget);
int attractor_setScale(GameObject* obj);
int attractor_getExtraSize(void);
int attractor_getObjectTypeId(void);
void attractor_free(GameObject* obj);
void attractor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void attractor_hitDetect(void);
void attractor_update(void);
void attractor_init(GameObject* obj, AttractorPlacement* placement);
void attractor_release(void);
void attractor_initialise(void);

extern ObjectDescriptor12 gAttractorObjDescriptor;

#endif /* MAIN_DLL_DLL_015F_ATTRACTOR_H_ */
