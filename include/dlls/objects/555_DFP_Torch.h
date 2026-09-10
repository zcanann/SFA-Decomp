#ifndef DLLS_OBJECTS_555_DFP_TORCH_H_
#define DLLS_OBJECTS_555_DFP_TORCH_H_

#include "dlls/object_descriptor.h"
#include "main/dll/dll_0069_modgfx.h"
#include "main/dll/partfx_interface.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

/* EN reads establish this prefix through the halfword at 0x1E.
 * The complete placement record size is not yet verified. */
typedef struct DfpTorchPlacementPrefix {
    ObjPlacement base; /* 0x00: common placement head */
    s8 rotPitch;       /* 0x18: low 6 bits seed anim.rotX (<<10) */
    u8 mode;           /* 0x19: torch mode selector */
    s16 motionRate;    /* 0x1A: root-motion scale numerator (nonpositive = default) */
    s16 colorIdx;      /* 0x1C: flame color index */
    s16 gameBit;       /* 0x1E: lit-state gamebit, -1 = none */
} DfpTorchPlacementPrefix;

STATIC_ASSERT(offsetof(DfpTorchPlacementPrefix, rotPitch) == 0x18);
STATIC_ASSERT(offsetof(DfpTorchPlacementPrefix, mode) == 0x19);
STATIC_ASSERT(offsetof(DfpTorchPlacementPrefix, motionRate) == 0x1A);
STATIC_ASSERT(offsetof(DfpTorchPlacementPrefix, colorIdx) == 0x1C);
STATIC_ASSERT(offsetof(DfpTorchPlacementPrefix, gameBit) == 0x1E);

/* DFP_Torch_getExtraSize proves the complete 0x10-byte state allocation. */
typedef struct DfpTorchState {
    int gameBit;      /* lit-state gamebit, -1 = none (def+0x1E) */
    s16 flickerTimer; /* 0x04 */
    s16 litTimer;     /* 0x06: 0x7D0 countdown while lit */
    u8 visibleLatch;  /* 0x08 */
    u8 mode;          /* 0x09: def+0x19 */
    u8 lit;           /* 0x0A */
    u8 sfxPending;    /* 0x0B */
    u8 prevLit;       /* 0x0C */
    u8 colorIdx;      /* 0x0D: def+0x1C */
    u8 unk0E[2];
} DfpTorchState;

STATIC_ASSERT(offsetof(DfpTorchState, gameBit) == 0x00);
STATIC_ASSERT(offsetof(DfpTorchState, flickerTimer) == 0x04);
STATIC_ASSERT(offsetof(DfpTorchState, litTimer) == 0x06);
STATIC_ASSERT(offsetof(DfpTorchState, visibleLatch) == 0x08);
STATIC_ASSERT(offsetof(DfpTorchState, mode) == 0x09);
STATIC_ASSERT(offsetof(DfpTorchState, lit) == 0x0A);
STATIC_ASSERT(offsetof(DfpTorchState, sfxPending) == 0x0B);
STATIC_ASSERT(offsetof(DfpTorchState, prevLit) == 0x0C);
STATIC_ASSERT(offsetof(DfpTorchState, colorIdx) == 0x0D);
STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

/* Geometry and flicker parameters share the render scratch lifetime. */
typedef struct DfpTorchRenderWork {
    f32 traceEnd[3];
    f32 traceStart[3];
    f32 cameraDirection[3];
    PartFxSpawnParams flickerParams;
} DfpTorchRenderWork;

/* DLL 105 reads only positionY for these source-backed flame spawns. */
typedef struct DfpTorchFlameSpawnPrefix {
    u8 unused00[0x10];
    f32 positionY;
} DfpTorchFlameSpawnPrefix;

STATIC_ASSERT(offsetof(DfpTorchFlameSpawnPrefix, positionY) == 0x10);

extern u8 gDfpTorchSequenceState;
extern const Dll69EffectParams gDfpTorchEffectParams;
extern ObjectDescriptor gDFP_TorchObjDescriptor;

int DFP_Torch_getExtraSize(void);
int DFP_Torch_getObjectTypeId(void);
void DFP_Torch_free(GameObject* obj);
void DFP_Torch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Torch_hitDetect(void);
void DFP_Torch_update(GameObject* obj);
void DFP_Torch_init(GameObject* obj, DfpTorchPlacementPrefix* def);
void DFP_Torch_release(void);
void DFP_Torch_initialise(void);

#endif /* DLLS_OBJECTS_555_DFP_TORCH_H_ */
