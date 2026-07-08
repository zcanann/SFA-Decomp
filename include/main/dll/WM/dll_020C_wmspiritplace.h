#ifndef MAIN_DLL_WM_DLL_020C_WMSPIRITPLACE_H_
#define MAIN_DLL_WM_DLL_020C_WMSPIRITPLACE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmSpiritPlaceState
{
    f32 heightOffset;       /* 0x00: placement height / 32767 / 100 (not read back) */
    int unk_04;             /* 0x04: cleared at init, never read */
    s16 unk_08;             /* 0x08: cleared at init, never read */
    s16 unk_0A;             /* 0x0A: cleared at init, never read */
    s16 promptGameBit;      /* 0x0C: game bit arming the interaction prompt */
    s16 sequenceGameBit;    /* 0x0E: game bit granted when sequence 0 completes */
    s16 setupParam;         /* 0x10: from placement, never read */
    u8 fxFlags;             /* 0x12: WMSPIRITPLACE_FX_ACTIVE */
    u8 mapEventMode;        /* 0x13: world-map map-event mode, cached at init */
    u8 transitionDelay;     /* 0x14: frames until sequenceGameBit is set */
    u8 sequenceStarted : 1; /* 0x15 & 0x80: sequence 0 has run; lock interaction */
    u8 envFxPending : 1;    /* 0x15 & 0x40: place 5's one-shot env change due */
    u8 unusedFlags : 6;
    u8 pad16[2];
} WmSpiritPlaceState;

typedef struct WmSpiritPlaceMapData
{
    ObjPlacement base;
    s8 rotXByte;         /* 0x18: rotX in 1/256 turns */
    s8 setupParam;       /* 0x19 */
    s16 rotYAngle;       /* 0x1A: rotY in 1/256 turns */
    s16 heightOffset;    /* 0x1C */
    s16 sequenceGameBit; /* 0x1E */
    s16 promptGameBit;   /* 0x20 */
} WmSpiritPlaceMapData;

STATIC_ASSERT(offsetof(WmSpiritPlaceState, promptGameBit) == 0x0C);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, sequenceGameBit) == 0x0E);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, setupParam) == 0x10);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, transitionDelay) == 0x14);
STATIC_ASSERT(sizeof(WmSpiritPlaceState) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, setupParam) == 0x19);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, rotYAngle) == 0x1A);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, heightOffset) == 0x1C);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, sequenceGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, promptGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmSpiritPlaceMapData) == 0x24);

void wmspiritplace_onSeqFree(void);
int WM_spiritplace_SeqFn(int obj, int unused, ObjAnimUpdateState* actor);
int WM_spiritplace_getExtraSize(void);
int WM_spiritplace_getObjectTypeId(void);
void WM_spiritplace_free(void);
void WM_spiritplace_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_spiritplace_hitDetect(GameObject* obj);
void WM_spiritplace_update(GameObject* obj);
void WM_spiritplace_init(GameObject* obj, WmSpiritPlaceMapData* placement);
void WM_spiritplace_release(void);
void WM_spiritplace_initialise(void);

#endif /* MAIN_DLL_WM_DLL_020C_WMSPIRITPLACE_H_ */
