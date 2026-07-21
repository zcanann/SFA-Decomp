#ifndef MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_
#define MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

extern ObjectDescriptor gKaldaChompMeObjDescriptor;

typedef struct KaldaChompMeState
{
    f32 progress;
    f32 step;
    f32 targetProgress;
    u8 moveId;
    u8 pad0D[3];
} KaldaChompMeState;

typedef struct KaldaChompMePlacement
{
    ObjPlacement base;
    u8 rotZByte; /* 0x18 */
    u8 rotYByte; /* 0x19 */
    u8 rotXByte; /* 0x1A */
} KaldaChompMePlacement;

typedef u8 KaldaChompMeLinkedMode;
enum
{
    KALDACHOMPME_LINKED_MOVE_0 = 1,
    KALDACHOMPME_LINKED_MOVE_1 = 2
};

STATIC_ASSERT(offsetof(KaldaChompMeState, targetProgress) == 0x8);
STATIC_ASSERT(offsetof(KaldaChompMeState, moveId) == 0xC);
STATIC_ASSERT(sizeof(KaldaChompMeState) == 0x10);
STATIC_ASSERT(offsetof(KaldaChompMePlacement, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(KaldaChompMePlacement, rotYByte) == 0x19);
STATIC_ASSERT(offsetof(KaldaChompMePlacement, rotXByte) == 0x1A);
STATIC_ASSERT(sizeof(KaldaChompMePlacement) == 0x1C);

int KaldaChompMe_getExtraSize(void);
int KaldaChompMe_getObjectTypeId(void);
void KaldaChompMe_free(void);
void KaldaChompMe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderFlag);
void KaldaChompMe_hitDetect(void);
void KaldaChompMe_update(GameObject* obj);
void KaldaChompMe_init(GameObject* obj, KaldaChompMePlacement* placement);
void KaldaChompMe_release(void);
void KaldaChompMe_initialise(void);
void kaldachompme_setLinkedMouthMode(u8* obj, KaldaChompMeLinkedMode mode);

extern f32 gKaldaChompOne;
extern f32 gKaldaChompZero;
extern f32 gKaldaChompLinkedMouthStep;

#endif /* MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_ */
