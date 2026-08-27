#ifndef DLLS_OBJECTS_278_WM_COLUMN_H_
#define DLLS_OBJECTS_278_WM_COLUMN_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/carryable_state.h"

/* Only the accessed placement prefix is recovered; the complete retail width is not established. */
typedef struct WMColumnPlacement {
    ObjPlacement base;   /* 0x00 */
    u8 initialYaw;       /* 0x18 */
    u8 modelBankIndex;   /* 0x19: object ID is 500 plus its signed-byte view */
    u8 pad1A[4];         /* 0x1A */
    s16 occupiedGameBit; /* 0x1E: set while the matching column occupies this spot, or -1 */
} WMColumnPlacement;

STATIC_ASSERT(offsetof(WMColumnPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(WMColumnPlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(WMColumnPlacement, modelBankIndex) == 0x19);
STATIC_ASSERT(offsetof(WMColumnPlacement, pad1A) == 0x1A);
STATIC_ASSERT(offsetof(WMColumnPlacement, occupiedGameBit) == 0x1E);

int WM_Column_getExtraSize(void);
int WM_Column_getObjectTypeId(void);
void WM_Column_free(GameObject* obj);
void WM_Column_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void WM_Column_hitDetect(void);
void WM_Column_update(GameObject* obj);
void WM_Column_init(GameObject* obj, WMColumnPlacement* placement);
void WM_Column_release(void);
void WM_Column_initialise(void);

extern ObjectDescriptor gWM_ColumnObjDescriptor;

#endif /* DLLS_OBJECTS_278_WM_COLUMN_H_ */
