#ifndef MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_
#define MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_

#include "main/game_object.h"
#include "global.h"
#include "main/lightningeffect.h"
#include "main/obj_placement.h"

typedef struct DrLightBeaFlags
{
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrLightBeaFlags;

typedef struct DrlightbeaPlacement
{
    ObjPlacement base;
    u8 pad18;
    s8 targetId; /* 0x19: placed-object target id, or 0 to use the player */
    u8 pad1A[0x20 - 0x1A];
    s16 gameBit; /* 0x20: enables the beam while set */
    u8 pad22[0x28 - 0x22];
} DrlightbeaPlacement;

/* Per-object extra state block (DR_LightBea_getExtraSize == 0xc): holds the
 * lightningCreate buffer handle at 0 and the active/free bit flags at 4. */
typedef struct DrLightBeaState
{
    LightningEffect* handle; /* 0x00: lightningCreate buffer, or NULL */
    DrLightBeaFlags flags;   /* 0x04 */
} DrLightBeaState;

extern f32 lbl_803E6BB8;
extern f32 lbl_803E6BBC;
extern f32 lbl_803E6BC0;

int DR_LightBea_getExtraSize(void);
int DR_LightBea_getObjectTypeId(void);
void DR_LightBea_free(GameObject* obj);
void DR_LightBea_render(GameObject* obj, int p2, int p3, int p4, int p5);
void DR_LightBea_hitDetect(void);
void DR_LightBea_update(GameObject* obj);
void DR_LightBea_init(GameObject* obj);
void DR_LightBea_release(void);
void DR_LightBea_initialise(void);

#endif /* MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_ */
