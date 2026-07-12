#ifndef MAIN_DLL_DR_DLL_0281_DREARTHCAL_H
#define MAIN_DLL_DR_DLL_0281_DREARTHCAL_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct DREarthCalSetup
{
    ObjPlacement base;
    s8 yaw;
} DREarthCalSetup;

STATIC_ASSERT(offsetof(DREarthCalSetup, yaw) == 0x18);

extern ObjectDescriptor12 gDrEarthCalObjDescriptor;
extern f32 lbl_803E6C08;
extern f32 lbl_803E6C0C;
extern f32 lbl_803E6C10;
extern f32 lbl_803E6C14;
extern f32 lbl_803E6C18;
extern f32 lbl_803E6C1C;

int drearthcal_setScale(void);
int drearthcal_getExtraSize(void);
int drearthcal_getObjectTypeId(void);
void drearthcal_free(void);
void drearthcal_render(void);
void drearthcal_hitDetect(void);
void drearthcal_update(GameObject* obj);
void drearthcal_init(GameObject* obj, DREarthCalSetup* setup);
void drearthcal_release(void);
void drearthcal_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0281_DREARTHCAL_H */
