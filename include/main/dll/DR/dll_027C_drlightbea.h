#ifndef MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_
#define MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_

#include "global.h"
#include "main/lightningeffect.h"
#include "main/dll/dll_80220608_shared.h"

typedef struct DrlightbeaPlacement
{
    u8 pad0[0x19 - 0x0];
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

int DR_LightBea_getExtraSize(void);
int DR_LightBea_getObjectTypeId(void);
void DR_LightBea_free(int obj);
void DR_LightBea_render(int obj, int p2, int p3, int p4, int p5);
void DR_LightBea_hitDetect(void);
void DR_LightBea_update(int obj);
void DR_LightBea_init(int obj);
void DR_LightBea_release(void);
void DR_LightBea_initialise(void);

#endif /* MAIN_DLL_DR_DLL_027C_DRLIGHTBEA_H_ */
