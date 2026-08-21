#ifndef DLLS_OBJECTS_562_DFP_ROTATEP_H_
#define DLLS_OBJECTS_562_DFP_ROTATEP_H_

#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

typedef struct DFPRotatePPlacement {
  ObjPlacement base;     /* 0x00 */
  s8 rotXByte;           /* 0x18 */
  u8 unknown19;          /* 0x19 */
  u8 pad1A[0x1E - 0x1A]; /* 0x1A */
  s16 eventGameBit;      /* 0x1E */
  s16 activationGameBit; /* 0x20 */
} DFPRotatePPlacement;

typedef struct DFPRotatePStateFlags {
  u8 bit80 : 1;
  u8 bit40 : 1;
  u8 bit20 : 1;
  u8 bit10 : 1;
  u8 lowBits : 4;
} DFPRotatePStateFlags;

typedef struct DFPRotatePState {
  s16 eventId;
  union {
    s16 config20;
    s16 activationEventId;
  };
  union {
    s16 unk4;
    s16 variantSfxTimer;
  };
  u8 config19;
  u8 ringCount;
  DFPRotatePStateFlags flags;
} DFPRotatePState;

STATIC_ASSERT(offsetof(DFPRotatePPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DFPRotatePPlacement, unknown19) == 0x19);
STATIC_ASSERT(offsetof(DFPRotatePPlacement, eventGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DFPRotatePPlacement, activationGameBit) == 0x20);

extern GameObject* gDFP_RotatePEffectHandles[8];

int DFP_RotateP_getExtraSize(void);
int DFP_RotateP_getObjectTypeId(void);
void DFP_RotateP_render(void);
void DFP_RotateP_hitDetect(void);
void DFP_RotateP_update(GameObject* obj);
void DFP_RotateP_init(GameObject* obj, DFPRotatePPlacement* placement);
void DFP_RotateP_free(GameObject* obj, int arg1);
void DFP_RotateP_release(void);
void DFP_RotateP_initialise(void);
void DFP_RotateP_updateEffectHandleRing(GameObject* obj);
int DFP_RotateP_ensureEffectHandlePair(GameObject* obj, u8 ringIndex);
int DFP_RotateP_activateEffectHandleRing(GameObject* obj, int unused, ObjSeqState* animUpdate);

#endif /* DLLS_OBJECTS_562_DFP_ROTATEP_H_ */
