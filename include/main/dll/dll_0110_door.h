#ifndef MAIN_DLL_DLL_0110_DOOR_H_
#define MAIN_DLL_DLL_0110_DOOR_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

/* Retail DLL 0x110 door placements are uniformly 9 words: the common head
   followed by this exact 0x0C-byte parameter tail. */
typedef struct DoorPlacement {
    ObjPlacement base;          /* 0x00 */
    s16 closeRequestGameBit;    /* 0x18: nonzero requests that the door close */
    s16 closedLatchGameBit;     /* 0x1A: set after closing, cleared after opening */
    s16 triggerSequenceId;      /* 0x1C */
    u8 runSequenceId;           /* 0x1E */
    u8 rotXByte;                /* 0x1F: high byte of initial anim.rotX */
    u8 triggerArg;              /* 0x20: low 7 bits passed to preempt sequence */
    u8 rootMotionScaleInput;    /* 0x21: scale in 1/64 units */
    s16 closeReadyGameBit;      /* 0x22: closure waits for this bit, or -1 */
} DoorPlacement;

STATIC_ASSERT(offsetof(DoorPlacement, closeRequestGameBit) == 0x18);
STATIC_ASSERT(offsetof(DoorPlacement, rootMotionScaleInput) == 0x21);
STATIC_ASSERT(offsetof(DoorPlacement, closeReadyGameBit) == 0x22);
STATIC_ASSERT(sizeof(DoorPlacement) == 0x24);

typedef struct DoorState {
    u16 movementSfx; /* 0x0: looping sfx played while opening/closing */
    u16 endpointSfx; /* 0x2: sfx played when fully opened or closed */
    u8 phase;        /* 0x4: DOOR_PHASE_* */
    u8 initPending;  /* 0x5: Door_update one-shot trigger flag */
    u8 closeFlags;   /* 0x6: DOOR_CLOSE_FLAG_* */
    u8 pad7;
} DoorState;

STATIC_ASSERT(offsetof(DoorState, phase) == 0x4);
STATIC_ASSERT(offsetof(DoorState, closeFlags) == 0x6);
STATIC_ASSERT(sizeof(DoorState) == 0x8);

int Door_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int Door_getExtraSize(void);
void Door_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Door_update(GameObject* obj);
void Door_init(GameObject* obj, DoorPlacement* placement);

extern ObjectDescriptor gDoorObjDescriptor;

#endif /* MAIN_DLL_DLL_0110_DOOR_H_ */
