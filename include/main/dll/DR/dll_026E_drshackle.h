#ifndef MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_
#define MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_

#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "global.h"
#include "main/dll/DR/dr_types.h"
#include "main/objseq.h"

#define DRSHACKLE_OBJGROUP 0x37

typedef struct DrshacklePlacement
{
    ObjPlacement base;
    s8 startPathPoint;    /* 0x18: seeds pathPointA (only its parity is used) */
    s8 attachSlot;        /* 0x19: which of the HighTop's four shackle path-point slots this chain occupies */
    s16 pathObjGroupBase; /* 0x1A: base id of the path objects this chain binds */
    s16 quarterTurns;     /* 0x1C: rotZ in quarter turns; ==1 also selects two slots */
    s16 activeGameBit;    /* 0x1E: game bit that keeps the chain active */
} DrshacklePlacement;

typedef struct DrshackleState
{
    GameObject* pathSlots[2]; /* 0x00: the path-point objects this chain is bound to */
    union {
        struct
        {
            f32 savedPosX; /* 0x08 */
            f32 savedPosY; /* 0x0C */
            f32 savedPosZ; /* 0x10 */
        };
        Vec3f savedPos;
    };
    s32 slotCount;    /* 0x14: number of path slots (1 or 2) */
    u8 pad18[0x19 - 0x18];
    s8 unk19;              /* 0x19 */
    BitFlags8 flags1A;     /* 0x1A: b0 = chain active (visible) */
    u8 pathPointA;         /* 0x1B: path-point index of slot 0 */
    u8 pathPointB;         /* 0x1C: path-point index of slot 1 */
    u8 pad1D[0x20 - 0x1D];
} DrshackleState;

STATIC_ASSERT(offsetof(DrshackleState, flags1A) == 0x1A);
STATIC_ASSERT(offsetof(DrshacklePlacement, startPathPoint) == 0x18);
STATIC_ASSERT(offsetof(DrshacklePlacement, attachSlot) == 0x19);
STATIC_ASSERT(offsetof(DrshacklePlacement, pathObjGroupBase) == 0x1A);
STATIC_ASSERT(offsetof(DrshacklePlacement, quarterTurns) == 0x1C);
STATIC_ASSERT(offsetof(DrshacklePlacement, activeGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrshackleState, savedPosX) == 0x08);
STATIC_ASSERT(offsetof(DrshackleState, slotCount) == 0x14);
STATIC_ASSERT(offsetof(DrshackleState, pathPointA) == 0x1B);
STATIC_ASSERT(offsetof(DrshackleState, pathPointB) == 0x1C);
STATIC_ASSERT(sizeof(DrshackleState) == 0x20);

/* gDrShackleObjDescriptor from slot02 onwards: the export table other objects
   reach through obj->anim.dll. */
typedef struct DrshackleInterface
{
    void* pad00[8];
    void (*renderAtPathPoint)(GameObject* shackle, void* owner, int pathPoint, int p2, int p3, int p4, int p5);
    int (*getAttachSlot)(GameObject* shackle);
} DrshackleInterface;

#define DRSHACKLE_INTERFACE(shackle) ((DrshackleInterface*)*((GameObject*)(shackle))->anim.dll)

STATIC_ASSERT(offsetof(DrshackleInterface, renderAtPathPoint) == 0x20);
STATIC_ASSERT(offsetof(DrshackleInterface, getAttachSlot) == 0x24);

extern int gDrShackleRotZOffset;
extern int lbl_803DDD70;

int drshackle_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
int drshackle_getAttachSlot(GameObject* obj);
int drshackle_renderAtPathPoint(GameObject* obj, int a, int b, int c, int d, int e, int f);
int drshackle_getExtraSize(void);
int drshackle_getObjectTypeId(void);
void drshackle_free(GameObject* obj);
void drshackle_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void drshackle_hitDetect(GameObject* obj);
void drshackle_update(GameObject* obj);
void drshackle_init(GameObject* obj, char* arg);
void drshackle_release(void);
void drshackle_initialise(void);

#endif /* MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_ */
