#ifndef MAIN_DLL_DF_DLL_022A_DFPOBJCREATOR_H_
#define MAIN_DLL_DF_DLL_022A_DFPOBJCREATOR_H_

#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
typedef struct DfpobjcreatorObjectDef
{
    ObjPlacement head; /* 0x00 */
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnPeriod;
    s8 rotXByte;
    s8 unk1F;
    u8 unk20;
    u8 pad21[0x24 - 0x21];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;

extern ObjectDescriptor gDFP_ObjCreatorObjDescriptor;

int DFP_ObjCreator_getExtraSize(void);
int DFP_ObjCreator_getObjectTypeId(void);
void DFP_ObjCreator_free(GameObject* obj, int flag);
void DFP_ObjCreator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_ObjCreator_hitDetect(void);
void DFP_ObjCreator_update(GameObject* obj);
void DFP_ObjCreator_init(GameObject* obj, DfpobjcreatorObjectDef* def);
void DFP_ObjCreator_release(void);
void DFP_ObjCreator_initialise(void);

#endif /* MAIN_DLL_DF_DLL_022A_DFPOBJCREATOR_H_ */
