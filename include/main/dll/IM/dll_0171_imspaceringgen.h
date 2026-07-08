#ifndef MAIN_DLL_IM_DLL_0171_IMSPACERINGGEN_H_
#define MAIN_DLL_IM_DLL_0171_IMSPACERINGGEN_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

/* spawn buffer for the loose ring pieces (Obj_AllocObjectSetup(0x24)).
   Head is the common ObjPlacement; the tail is file-local. */
typedef struct ImSpaceRingSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s8 spinPhase;      /* 0x18 */
    u8 pad19;          /* 0x19 */
    s16 spinSpeed;     /* 0x1A */
    s16 tiltSpeed;     /* 0x1C */
    u8 pad1E[0x24 - 0x1E];
} ImSpaceRingSetup;

STATIC_ASSERT(offsetof(ImSpaceRingSetup, spinPhase) == 0x18);
STATIC_ASSERT(offsetof(ImSpaceRingSetup, spinSpeed) == 0x1A);
STATIC_ASSERT(offsetof(ImSpaceRingSetup, tiltSpeed) == 0x1C);
STATIC_ASSERT(sizeof(ImSpaceRingSetup) == 0x24);

/* per-object extra (getExtraSize == 0xc) */
typedef struct RingGenState
{
    GameObject* ringA; /* 0x00 */
    GameObject* ringB; /* 0x04 */
    u8 visible;        /* 0x08: ring B currently visible */
} RingGenState;

STATIC_ASSERT(sizeof(RingGenState) == 0xc);

int IMSpaceRingGen_getExtraSize(void);
int IMSpaceRingGen_getObjectTypeId(void);
void IMSpaceRingGen_free(void);
void IMSpaceRingGen_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void IMSpaceRingGen_hitDetect(void);
void IMSpaceRingGen_update(GameObject* obj);
void IMSpaceRingGen_init(GameObject* obj);
void IMSpaceRingGen_release(void);
void IMSpaceRingGen_initialise(void);

#endif
