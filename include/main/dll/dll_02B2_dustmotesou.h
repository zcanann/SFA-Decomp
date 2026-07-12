#ifndef MAIN_DLL_DUSTMOTESOU_H_
#define MAIN_DLL_DUSTMOTESOU_H_

#include "global.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"

#define DUSTMOTESOU_DLL_ID 0x02B2
#define DUSTMOTESOU_CLASS_ID 0x007E
#define DUSTMOTESOU_DEF_ID 0x05A0
#define TAILLIGHTSO_DEF_ID 0x05A1
#define FIREWORKSOU_DEF_ID 0x05A2
#define DUSTMOTESOU_OBJECT_DEF_BYTES 0xA0
#define DUSTMOTESOU_PLACEMENT_BYTES 0x30

#define DUSTMOTESOU_SEQ_DUST_MOTE 0x0802
#define DUSTMOTESOU_SEQ_TAIL_LIGHT 0x0807
#define DUSTMOTESOU_SEQ_FIREWORK 0x080E

#define DUSTMOTESOU_OBJECT_FLAG_SPAWN_EFFECTS 0x2000
#define DUSTMOTESOU_BURST_BOX 0
#define DUSTMOTESOU_BURST_ARCED 1

typedef struct DustMoteSouMapData {
  u8 pad00[0x18];
  u8 rotZ;
  u8 rotY;
  u8 rotX;
  u8 effectId;
  u8 effectParamA;
  u8 effectParamB;
  u8 pad1E[0x20 - 0x1E];
  f32 scale;
  s16 gameBit;
  u8 spreadX;
  u8 spreadY;
  u8 spreadZ;
  u8 effectFlags;
  u8 burstMode;
  u8 pad2B[DUSTMOTESOU_PLACEMENT_BYTES - 0x2B];
} DustMoteSouMapData;

typedef struct DustMoteSouObject {
  ObjAnimComponent objAnim;
  u16 objectFlags;
} DustMoteSouObject;

STATIC_ASSERT(sizeof(DustMoteSouMapData) == DUSTMOTESOU_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(DustMoteSouMapData, rotZ) == 0x18);
STATIC_ASSERT(offsetof(DustMoteSouMapData, effectId) == 0x1B);
STATIC_ASSERT(offsetof(DustMoteSouMapData, scale) == 0x20);
STATIC_ASSERT(offsetof(DustMoteSouMapData, gameBit) == 0x24);
STATIC_ASSERT(offsetof(DustMoteSouMapData, spreadX) == 0x26);
STATIC_ASSERT(offsetof(DustMoteSouMapData, effectFlags) == 0x29);
STATIC_ASSERT(offsetof(DustMoteSouMapData, burstMode) == 0x2A);

STATIC_ASSERT(offsetof(DustMoteSouObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(DustMoteSouObject, objectFlags) == 0xB0);

extern ObjectDescriptor gDustMoteSouObjDescriptor;

int dustmotesou_getExtraSize(void);
int dustmotesou_getObjectTypeId(void);
void dustmotesou_free(DustMoteSouObject* obj);
void dustmotesou_render(DustMoteSouObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dustmotesou_hitDetect(void);
void dustmotesou_update(DustMoteSouObject* obj);
void dustmotesou_init(DustMoteSouObject* obj, DustMoteSouMapData* setup);
void dustmotesou_release(void);
void dustmotesou_initialise(void);

#endif /* MAIN_DLL_DUSTMOTESOU_H_ */
