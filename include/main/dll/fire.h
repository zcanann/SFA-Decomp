#ifndef MAIN_DLL_FIRE_H_
#define MAIN_DLL_FIRE_H_

#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

#define LINKA_LEVCONTROL_OBJECT_DEF_ID 0x0342
#define LINKA_LEVCONTROL_DLL_ID 0x0238
#define LINKA_LEVCONTROL_CLASS_ID 0x0030
#define LINKA_LEVCONTROL_OBJECT_DEF_SIZE 0xC0
#define LINKA_LEVCONTROL_PLACEMENT_SIZE 0x24

typedef struct LinkALevelControlObject LinkALevelControlObject;
typedef LinkALevelControlObject FireObject;

typedef undefined4 (*LinkALevelControlAnimEventCallback)(
    LinkALevelControlObject *obj, undefined4 unused,
    ObjAnimUpdateState *animUpdate);

struct LinkALevelControlObject {
    u8 pad00[0xAC];
    s8 mapEventMapId;
    u8 padAD[0xB0 - 0xAD];
    u16 flags;
    u8 padB2[0xBC - 0xB2];
    LinkALevelControlAnimEventCallback animEventCallback;
};

typedef struct LinkALevelControlTriggerInterface {
  u8 pad00[0x48];
  void (*refresh)(int mode, LinkALevelControlObject *obj, int mask);
} LinkALevelControlTriggerInterface;

typedef LinkALevelControlTriggerInterface FireObjectInterface;

STATIC_ASSERT(offsetof(LinkALevelControlObject, mapEventMapId) == 0xAC);
STATIC_ASSERT(offsetof(LinkALevelControlObject, flags) == 0xB0);
STATIC_ASSERT(offsetof(LinkALevelControlObject, animEventCallback) == 0xBC);
STATIC_ASSERT(offsetof(LinkALevelControlTriggerInterface, refresh) == 0x48);

extern ObjectDescriptor gFireObjDescriptor;

undefined4 fire_updateState(FireObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
int fireObj_getExtraSize(void);
int fireObj_getObjectTypeId(void);
void fireObj_free(void);
void fireObj_render(void);
void fireObj_hitDetect(void);
void fireObj_update(FireObject *obj);
void fireObj_init(FireObject *obj);
void fireObj_release(void);
void fireObj_initialise(void);

#endif /* MAIN_DLL_FIRE_H_ */
