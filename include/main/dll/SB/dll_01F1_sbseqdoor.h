#ifndef MAIN_DLL_SB_DLL_01F1_SBSEQDOOR_H_
#define MAIN_DLL_SB_DLL_01F1_SBSEQDOOR_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

/* Placement record: heading byte + a nonzero->bankIndex selector. */
typedef struct SBSeqDoorPlacement
{
    ObjPlacement head; /* 0x00 */
    s8 rotXByte;   /* 0x18: heading, scaled to anim.rotX (<<8) */
    s8 bankSelect; /* 0x19: nonzero picks bank index 1 */
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} SBSeqDoorPlacement;

STATIC_ASSERT(offsetof(SBSeqDoorPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SBSeqDoorPlacement, bankSelect) == 0x19);
STATIC_ASSERT(sizeof(SBSeqDoorPlacement) == 0x20);

int SB_SeqDoor_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int SB_SeqDoor_getExtraSize(void);
int SB_SeqDoor_getObjectTypeId(void);
void SB_SeqDoor_free(void);
void SB_SeqDoor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_SeqDoor_hitDetect(void);
void SB_SeqDoor_update(GameObject* obj);
void SB_SeqDoor_init(GameObject* obj, SBSeqDoorPlacement* placement);
void SB_SeqDoor_release(void);
void SB_SeqDoor_initialise(void);

extern ObjectDescriptor gSB_SeqDoorObjDescriptor;

#endif /* MAIN_DLL_SB_DLL_01F1_SBSEQDOOR_H_ */
