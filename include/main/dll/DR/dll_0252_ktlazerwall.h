#ifndef MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_
#define MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_

#include "global.h"

typedef struct KtlazerwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 intensityBit;  /* 0x1A: game bit; its value is the wall's intensity */
    s16 fireThreshold; /* 0x1C: intensity at/above which the wall fires */
    s16 activeBit;     /* 0x1E: game bit set while the lightning arc is live */
} KtlazerwallPlacement;

/* overlays the object's extra block; the low flags byte lives at offset 0
   (pad0) and is accessed as a u8 array elsewhere. */
typedef struct KtlazerwallState
{
    u8 pad0[0x4 - 0x0];
    f32 reloadTimer; /* 0x04: counts down between arc-snap sfx */
    f32 driftTimer;  /* 0x08: render-side bolt reposition timer */
    f32 driftSpeed;  /* 0x0C: signed bolt drift speed */
    s32 bolt;        /* 0x10: lightning bolt allocation (pointer) */
} KtlazerwallState;

int KT_Lazerwall_getExtraSize(void);
int KT_Lazerwall_getObjectTypeId(void);
void KT_Lazerwall_free(struct GameObject *obj);
void KT_Lazerwall_render(struct GameObject *obj);
void KT_Lazerwall_hitDetect(void);
void KT_Lazerwall_update(int obj);
void KT_Lazerwall_init(struct GameObject *obj, char* placement);
void KT_Lazerwall_release(void);
void KT_Lazerwall_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_ */
