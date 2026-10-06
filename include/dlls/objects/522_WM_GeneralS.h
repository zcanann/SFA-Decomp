#ifndef DLLS_OBJECTS_522_WM_GENERALS_H_
#define DLLS_OBJECTS_522_WM_GENERALS_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

struct ObjSeqState;

typedef enum WmGeneralScalesPhase {
    WM_GENERAL_SCALES_PHASE_IDLE = 0,
    WM_GENERAL_SCALES_PHASE_HIDDEN = 1,
    WM_GENERAL_SCALES_PHASE_SLAM_A = 2,
    WM_GENERAL_SCALES_PHASE_SLAM_B = 3,
} WmGeneralScalesPhase;

/* WM_GeneralScales_getExtraSize() allocates this complete 0x08-byte state. */
typedef struct WmGeneralScalesState {
    f32 unknown00; /* Set to 0.0 or 800.0 by the slam events. */
    u8 phase;      /* WmGeneralScalesPhase */
    u8 fadeAlpha;  /* Zero is invisible; nonzero values ramp each frame. */
    u8 unknown06[2];
} WmGeneralScalesState;

STATIC_ASSERT(offsetof(WmGeneralScalesState, unknown00) == 0x00);
STATIC_ASSERT(offsetof(WmGeneralScalesState, phase) == 0x04);
STATIC_ASSERT(offsetof(WmGeneralScalesState, fadeAlpha) == 0x05);
STATIC_ASSERT(offsetof(WmGeneralScalesState, unknown06) == 0x06);
STATIC_ASSERT(sizeof(WmGeneralScalesState) == 0x08);

int WM_GeneralScales_sequenceCallback(GameObject* objectHandle, int unusedArg2, struct ObjSeqState* animUpdate);
int WM_GeneralScales_getExtraSize(void);
int WM_GeneralScales_getObjectTypeId(void);
void WM_GeneralScales_free(GameObject* obj);
void WM_GeneralScales_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible);
void WM_GeneralScales_hitDetect(void);
void WM_GeneralScales_update(void);
void WM_GeneralScales_init(GameObject* obj);
void WM_GeneralScales_release(void);
void WM_GeneralScales_initialise(void);

extern ObjectDescriptor gWM_GeneralScalesObjDescriptor;

#endif /* DLLS_OBJECTS_522_WM_GENERALS_H_ */
