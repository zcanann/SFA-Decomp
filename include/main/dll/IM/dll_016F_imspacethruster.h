#ifndef MAIN_DLL_IM_DLL_016F_IMSPACETHRUSTER_H_
#define MAIN_DLL_IM_DLL_016F_IMSPACETHRUSTER_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef enum ImSpaceThrusterPhase
{
    IMSPACETHRUSTER_PHASE_OFF = 0,
    IMSPACETHRUSTER_PHASE_ON = 1,
    IMSPACETHRUSTER_PHASE_FADE_OUT = 2,
} ImSpaceThrusterPhase;

/* Class-specific placement record: ObjPlacement common head (0x00..0x17)
 * followed by this thruster's setup fields. */
typedef struct ImSpaceThrusterPlacement
{
    ObjPlacement head;
    s8 rotX;       /* 0x18: high byte of the spawn rotX */
    u8 kind;       /* 0x19: thruster kind 0..6 */
    s16 rotY;      /* 0x1a */
    s16 bankIndex; /* 0x1c */
} ImSpaceThrusterPlacement;

STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, rotY) == 0x1a);
STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, bankIndex) == 0x1c);

typedef s16 (*ImSpaceThrusterGetModeFn)(GameObject* parent, int kind);
typedef void (*ImSpaceThrusterSetWeightFn)(GameObject* parent, f32 weight, int kind);

typedef struct ImSpaceThrusterParentInterface
{
    void* standardSlots[8];
    ImSpaceThrusterGetModeFn getThrusterMode;
    void* slot09;
    ImSpaceThrusterSetWeightFn setThrusterWeight;
} ImSpaceThrusterParentInterface;

STATIC_ASSERT(offsetof(ImSpaceThrusterParentInterface, getThrusterMode) == 0x20);
STATIC_ASSERT(offsetof(ImSpaceThrusterParentInterface, setThrusterWeight) == 0x28);

#define IM_SPACE_THRUSTER_PARENT_INTERFACE(parent) \
    ((ImSpaceThrusterParentInterface*)*((GameObject*)(parent))->anim.dll)

int imspacethruster_getExtraSize(void);
int imspacethruster_getObjectTypeId(void);
void imspacethruster_free(GameObject* obj);
void imspacethruster_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void imspacethruster_hitDetect(void);
void imspacethruster_update(GameObject* obj);
void imspacethruster_init(GameObject* obj, ImSpaceThrusterPlacement* placement);
void imspacethruster_release(void);
void imspacethruster_initialise(void);

extern ObjectDescriptor gIMSpaceThrusterObjDescriptor;

#endif
