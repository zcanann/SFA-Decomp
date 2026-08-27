#ifndef DLLS_OBJECTS_478_DIM2LAVACON_H_
#define DLLS_OBJECTS_478_DIM2LAVACON_H_

#include "dlls/object_descriptor.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define DIM2_LAVA_CONTROL_HEAT_ALPHA_TARGET_COUNT 8
#define DIM2_GAMEBIT_AREA_MUSIC_ACTIVE            0xDA5

/*
 * The active-target retail placement files are unavailable. This type models
 * only the prefix read by DIM2LavaCon; it does not claim a complete placement
 * width.
 */
typedef struct Dim2LavaControlPlacementView {
    ObjPlacement base;
    u8 unknown18[2];
    s16 countdownInitialValue;
    s16 unknown1C;
    s16 completionGameBit;
} Dim2LavaControlPlacementView;

/* dim2lavacontrol_getExtraSize() allocates the complete 0x10-byte state. */
typedef struct Dim2LavaControlState {
    s8 countdown;
    u8 savedCountdown;
    s8 statusFlags;
    u8 heatEffectAlpha;
    u8 phase;
    u8 unknown05[3];
    GameBitLatchState musicLatch;
    int musicTriggerId;
} Dim2LavaControlState;

/* gDIM2LavaControlObjDescriptor from slot02 onwards: the export table other
 * objects reach through obj->anim.dll. */
typedef struct Dim2LavaControlInterface {
    ObjectInterface object;
    void (*tickCountdown)(GameObject* obj);
} Dim2LavaControlInterface;

typedef struct Dim2LavaControlDescriptor {
    ObjectDescriptor descriptor;
    void (*tickCountdown)(GameObject* obj);
    ObjectDescriptorCallback slot0B;
} Dim2LavaControlDescriptor;

#define DIM2_LAVA_CONTROL_INTERFACE(control) ((Dim2LavaControlInterface*)*((GameObject*)(control))->anim.dll)

STATIC_ASSERT(offsetof(Dim2LavaControlPlacementView, base) == 0x00);
STATIC_ASSERT(offsetof(Dim2LavaControlPlacementView, unknown18) == 0x18);
STATIC_ASSERT(offsetof(Dim2LavaControlPlacementView, countdownInitialValue) == 0x1A);
STATIC_ASSERT(offsetof(Dim2LavaControlPlacementView, unknown1C) == 0x1C);
STATIC_ASSERT(offsetof(Dim2LavaControlPlacementView, completionGameBit) == 0x1E);

STATIC_ASSERT(offsetof(Dim2LavaControlState, countdown) == 0x00);
STATIC_ASSERT(offsetof(Dim2LavaControlState, savedCountdown) == 0x01);
STATIC_ASSERT(offsetof(Dim2LavaControlState, statusFlags) == 0x02);
STATIC_ASSERT(offsetof(Dim2LavaControlState, heatEffectAlpha) == 0x03);
STATIC_ASSERT(offsetof(Dim2LavaControlState, phase) == 0x04);
STATIC_ASSERT(offsetof(Dim2LavaControlState, unknown05) == 0x05);
STATIC_ASSERT(offsetof(Dim2LavaControlState, musicLatch) == 0x08);
STATIC_ASSERT(offsetof(Dim2LavaControlState, musicTriggerId) == 0x0C);
STATIC_ASSERT(sizeof(Dim2LavaControlState) == 0x10);

STATIC_ASSERT(offsetof(Dim2LavaControlInterface, object) == 0x00);
STATIC_ASSERT(offsetof(Dim2LavaControlInterface, tickCountdown) == 0x20);
STATIC_ASSERT(sizeof(Dim2LavaControlInterface) == 0x24);

STATIC_ASSERT(offsetof(Dim2LavaControlDescriptor, descriptor) == 0x00);
STATIC_ASSERT(offsetof(Dim2LavaControlDescriptor, tickCountdown) == 0x38);
STATIC_ASSERT(offsetof(Dim2LavaControlDescriptor, slot0B) == 0x3C);
STATIC_ASSERT(sizeof(Dim2LavaControlDescriptor) == 0x40);

void dim2lavacontrol_tickCountdown(GameObject* obj);
int dim2lavacontrol_getExtraSize(void);
void dim2lavacontrol_free(void);
void dim2lavacontrol_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void dim2lavacontrol_update(GameObject* obj);
void dim2lavacontrol_init(GameObject* obj, const Dim2LavaControlPlacementView* placement);

extern u8 gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_ALPHA_TARGET_COUNT];
extern Dim2LavaControlDescriptor gDIM2LavaControlObjDescriptor;

#endif /* DLLS_OBJECTS_478_DIM2LAVACON_H_ */
