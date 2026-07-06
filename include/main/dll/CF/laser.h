#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "global.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

#define LASER_UNSUPPORTED_DLL_ID 0x0236
#define LASER_UNSUPPORTED_OBJECT_CLASS_ID 0x0030
#define LASER_UNSUPPORTED_OBJECT_DEF_DFP_LASERBE 0x0355

typedef struct LaserState {
  s16 completionGameBit;
  s16 activationGameBit;
  u8 completionLatched;
} LaserState;

typedef struct LaserObjectMapData {
  ObjPlacement base;
  s8 mapEventSlot;
  u8 pad19[0x1E - 0x19];
  s16 completionGameBit;
  s16 activationGameBit;
} LaserObjectMapData;

typedef struct LaserObject {
  union {
    ObjAnimComponent anim;
    struct {
      s16 modeWord;
      u8 pad02[0xAC - 2];
      s8 mapEventSlot;
      u8 padAD[0xAF - 0xAD];
      u8 statusFlags;
    };
  };
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  LaserState *state;
} LaserObject;

typedef GameUIInterface LaserTriggerInterface;

typedef struct LaserReleaseInterface {
  u8 pad00[0x48];
  void (*releaseObject)(int parent, void *object, int flags);
} LaserReleaseInterface;

STATIC_ASSERT(sizeof(LaserState) == 0x06);
STATIC_ASSERT(offsetof(LaserState, completionGameBit) == 0x00);
STATIC_ASSERT(offsetof(LaserState, activationGameBit) == 0x02);
STATIC_ASSERT(offsetof(LaserState, completionLatched) == 0x04);

STATIC_ASSERT(offsetof(LaserObjectMapData, mapEventSlot) == 0x18);
STATIC_ASSERT(offsetof(LaserObjectMapData, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(LaserObjectMapData, activationGameBit) == 0x20);
STATIC_ASSERT(sizeof(LaserObjectMapData) == 0x24);

STATIC_ASSERT(offsetof(LaserObject, anim) == 0x00);
STATIC_ASSERT(offsetof(LaserObject, modeWord) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(LaserObject, mapEventSlot) == offsetof(ObjAnimComponent, mapEventSlot));
STATIC_ASSERT(offsetof(LaserObject, statusFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(LaserObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(LaserObject, state) == 0xB8);

STATIC_ASSERT(offsetof(LaserReleaseInterface, releaseObject) == 0x48);

#define LASER_OBJECT_STATUS_ACTIVE 0x01
#define LASER_OBJECT_STATUS_DISABLED 0x08
#define LASER_OBJECT_FLAGS_SEQUENCE_CONTROL 0x6000

#define LASEROBJ_MODE_SEQUENCE_A 1
#define LASEROBJ_MODE_SEQUENCE_B 2
#define LASEROBJ_MODE_WORD_SHIFT 8

#define LASEROBJ_SEQUENCE_A_EVENT 0x2e8
#define LASEROBJ_SEQUENCE_B_EVENT 0x83c
#define LASEROBJ_SEQUENCE_B_MODE_MAP_A 7
#define LASEROBJ_SEQUENCE_B_MODE_MAP_B 0xd
#define LASEROBJ_SEQUENCE_B_MODE_A 8
#define LASEROBJ_SEQUENCE_B_MODE_B 2

#define LASEROBJ_MAIN_SEQUENCE_A_EVENT 0x123
#define LASEROBJ_MAIN_SEQUENCE_B_EVENT 0x83b

extern char sLaserInitNoLongerSupported[];
extern ObjectDescriptor gLaserUnsupportedObjDescriptor;
extern ObjectDescriptor gLaserObjDescriptor;

int laser_getExtraSize(void);
int laser_getObjectTypeId(void);
void laser_freeUnsupported(void);
void laser_renderUnsupported(void);
void laser_hitDetectUnsupported(void);
void laser_updateUnsupported(void);
void laser_init(void);
void laser_releaseUnsupported(void);
void laser_initialiseUnsupported(void);
int DFPSpPl_getExtraSize(void);
int DFPSpPl_getObjectTypeId(void);
void DFPSpPl_free(void);
void DFPSpPl_render(void);
void DFPSpPl_hitDetect(void);
void DFPSpPl_update(LaserObject *obj);
void DFPSpPl_init(LaserObject *obj,LaserObjectMapData *mapData);
void DFPSpPl_release(void);
void DFPSpPl_initialise(void);

#endif /* MAIN_DLL_CF_LASER_H_ */
