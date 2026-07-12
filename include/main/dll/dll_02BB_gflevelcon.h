#ifndef MAIN_DLL_DLL_02BB_GFLEVELCON_H_
#define MAIN_DLL_DLL_02BB_GFLEVELCON_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

/* Spawn-setup buffer for the arwing-projectile children (defNos
 * 0x80d/0x7e4/0x859). Reuses ObjPlacement's pos/color head and adds the
 * class-specific launch fields at 0x18/0x19/0x1a (all u8 stores per asm). */
typedef struct GfProjectileSetup
{
    ObjPlacement head; /* 0x00 */
    u8 roll;           /* 0x18: cleared to 0 */
    u8 pitch;          /* 0x19 */
    u8 yawHi;          /* 0x1a */
} GfProjectileSetup;

/* The next two typedefs are two views over the SAME 0x10-byte obj->extra
   allocation (gf_levelcon_getExtraSize returns 0x10). findLinkedObjects
   caches the three linked object handles as s32 ids (light, scrollA,
   scrollB); handleScriptEvents reads scrollA/scrollB back as
   s16* scroll-offset pointers and promptTimer as the prompt countdown. The split
   into two casts (with differing field types at scrollA/scrollB) is
   matching-required: collapsing to one struct changes the cast keys and
   the codegen. */
typedef struct GfLevelconFindLinkedObjectsState
{
    s32 light;
    s32 scrollA;
    s32 scrollB;
    u8 padC[0x10 - 0xC];
} GfLevelconFindLinkedObjectsState;

typedef struct GfLevelconHandleScriptEventsState
{
    void* light;
    void* scrollA;
    void* scrollB;
    f32 promptTimer;
} GfLevelconHandleScriptEventsState;

typedef struct GfHitState
{
    u8 pad0[0x88];
    int mode;
    u8 pad1[0x16];
    s16 pitchVel;
    s16 rollVel;
    u8 pad2[8];
    u8 hits[4];
    u8 timer[4];
    u8 pad3[3];
    u8 texState[3];
} GfHitState;

STATIC_ASSERT(offsetof(GfHitState, mode) == 0x88);
STATIC_ASSERT(offsetof(GfHitState, pitchVel) == 0xA2);
STATIC_ASSERT(offsetof(GfHitState, hits[0]) == 0xAE);
STATIC_ASSERT(offsetof(GfHitState, timer[0]) == 0xB2);
STATIC_ASSERT(offsetof(GfHitState, texState[0]) == 0xB9);

extern ObjectDescriptor gGF_LevelConObjDescriptor;
extern const f32 lbl_803E7460;
extern const f32 lbl_803E7464;
extern const f32 lbl_803E7468;
extern const f32 lbl_803E746C;
extern const f32 lbl_803E7470;
extern const f32 lbl_803E7474;
extern const f32 lbl_803E7478;
extern const f32 lbl_803E747C;
extern const f32 lbl_803E7480;
extern const f32 lbl_803E7484;
extern const f32 lbl_803E7488;
extern const f32 lbl_803E748C;

int gf_levelcon_SeqFn(GameObject* obj, int eventId, ObjAnimUpdateState* animUpdate);
int gf_levelcon_getExtraSize(void);
int gf_levelcon_getObjectTypeId(void);
void gf_levelcon_hitDetect(void);
void gf_levelcon_initialise(void);
void gf_levelcon_release(void);
void gf_levelcon_free(void);
void gf_levelcon_update(GameObject* obj);
void gf_levelcon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void gf_levelcon_init(GameObject* obj);
void gf_levelcon_findLinkedObjects(GameObject* obj);

#endif /* MAIN_DLL_DLL_02BB_GFLEVELCON_H_ */
