#ifndef MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_
#define MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_

#include "main/game_object.h"
#include "main/lightningeffect.h"
#include "main/obj_placement.h"
#include "global.h"

#define KT_LAZERWALL_FLAG_TRIGGERED   0x1
#define KT_LAZERWALL_FLAG_FIRING      0x4
#define KT_LAZERWALL_FLAG_BOLT_ACTIVE 0x8

typedef struct KtlazerwallPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 reserved19;
    s16 intensityBit;  /* 0x1A: game bit; its value is the wall's intensity */
    s16 fireThreshold; /* 0x1C: intensity at/above which the wall fires */
    s16 activeBit;     /* 0x1E: game bit set while the lightning arc is live */
} KtlazerwallPlacement;

/* overlays the object's extra block; the low flags byte lives at offset 0
   (pad0) and is accessed as a u8 array elsewhere. */
typedef struct KtlazerwallState
{
    u8 flags;
    u8 previousFlags;
    u8 reserved02[2];
    f32 reloadTimer; /* 0x04: counts down between arc-snap sfx */
    f32 driftTimer;  /* 0x08: render-side bolt reposition timer */
    f32 driftSpeed;  /* 0x0C: signed bolt drift speed */
    LightningEffect* bolt; /* 0x10 */
} KtlazerwallState;

STATIC_ASSERT(offsetof(KtlazerwallPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(KtlazerwallPlacement, intensityBit) == 0x1a);
STATIC_ASSERT(offsetof(KtlazerwallPlacement, activeBit) == 0x1e);
STATIC_ASSERT(sizeof(KtlazerwallPlacement) == 0x20);
STATIC_ASSERT(offsetof(KtlazerwallState, flags) == 0x0);
STATIC_ASSERT(offsetof(KtlazerwallState, reloadTimer) == 0x4);
STATIC_ASSERT(offsetof(KtlazerwallState, bolt) == 0x10);
STATIC_ASSERT(sizeof(KtlazerwallState) == 0x14);

union KtlazerwallConstF32 { f32 f; };
extern const union KtlazerwallConstF32 lbl_803E68B0;
extern const union KtlazerwallConstF32 lbl_803E68B4;
extern const union KtlazerwallConstF32 lbl_803E68B8;
extern const union KtlazerwallConstF32 lbl_803E68BC;

int KT_Lazerwall_getExtraSize(void);
int KT_Lazerwall_getObjectTypeId(void);
void KT_Lazerwall_free(GameObject* obj);
void KT_Lazerwall_render(GameObject* obj);
void KT_Lazerwall_hitDetect(void);
void KT_Lazerwall_update(GameObject* obj);
void KT_Lazerwall_init(GameObject* obj, KtlazerwallPlacement* placement);
void KT_Lazerwall_release(void);
void KT_Lazerwall_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0252_KTLAZERWALL_H_ */
