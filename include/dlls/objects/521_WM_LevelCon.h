#ifndef DLLS_OBJECTS_521_WM_LEVEL_CON_H_
#define DLLS_OBJECTS_521_WM_LEVEL_CON_H_

#include "dlls/object_descriptor.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "game/objects/object_fwd.h"

/* WM_LevelControl_getExtraSize() allocates this complete 0x1C-byte state. */
typedef struct WMLevelControlState {
    f32 messageTimer;      /* Intro-message frames remaining. */
    s16 mode4SpiritMarker; /* Set to -1 for map-event mode 4. */
    s16 spiritDelayFrames; /* Seeded to 0x1E, also copied from mode7DelayFrames. */
    s16 mode7TimerFrames;  /* Set to 700 for map-event mode 7. */
    u8 mode7DelayFrames;   /* Set to 0x1E for map-event mode 7. */
    u8 modeFlags;          /* Cleared during init. */
    u8 pad0C[4];
    GameBitLatchState musicLatch;
    u8 musicLatchesDisabled; /* Set for map-event mode 7. */
    u8 pad15[3];
    u32 frameCounter; /* Frames since init. */
} WMLevelControlState;

STATIC_ASSERT(offsetof(WMLevelControlState, messageTimer) == 0x00);
STATIC_ASSERT(offsetof(WMLevelControlState, mode4SpiritMarker) == 0x04);
STATIC_ASSERT(offsetof(WMLevelControlState, spiritDelayFrames) == 0x06);
STATIC_ASSERT(offsetof(WMLevelControlState, mode7TimerFrames) == 0x08);
STATIC_ASSERT(offsetof(WMLevelControlState, mode7DelayFrames) == 0x0A);
STATIC_ASSERT(offsetof(WMLevelControlState, modeFlags) == 0x0B);
STATIC_ASSERT(offsetof(WMLevelControlState, pad0C) == 0x0C);
STATIC_ASSERT(offsetof(WMLevelControlState, musicLatch) == 0x10);
STATIC_ASSERT(offsetof(WMLevelControlState, musicLatchesDisabled) == 0x14);
STATIC_ASSERT(offsetof(WMLevelControlState, pad15) == 0x15);
STATIC_ASSERT(offsetof(WMLevelControlState, frameCounter) == 0x18);
STATIC_ASSERT(sizeof(WMLevelControlState) == 0x1C);

void WM_LevelControl_updateSkyLighting(GameObject* obj);
int WM_LevelControl_getExtraSize(void);
int WM_LevelControl_getObjectTypeId(void);
void WM_LevelControl_free(GameObject* obj);
void WM_LevelControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void WM_LevelControl_hitDetect(void);
void WM_LevelControl_update(GameObject* obj);
void WM_LevelControl_init(GameObject* obj);
void WM_LevelControl_release(void);
void WM_LevelControl_initialise(void);

extern ObjectDescriptor gWM_LevelControlObjDescriptor;

#endif /* DLLS_OBJECTS_521_WM_LEVEL_CON_H_ */
