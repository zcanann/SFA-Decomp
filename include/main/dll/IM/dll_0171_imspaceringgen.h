#ifndef MAIN_DLL_IM_DLL_0171_IMSPACERINGGEN_H_
#define MAIN_DLL_IM_DLL_0171_IMSPACERINGGEN_H_

#include "main/dll/IM/dll_0170_imspacering.h"

/* per-object extra (getExtraSize == 0xc) */
typedef struct RingGenState
{
    GameObject* ringA; /* 0x00 */
    GameObject* ringB; /* 0x04 */
    u8 visible;        /* 0x08: ring B currently visible */
} RingGenState;

STATIC_ASSERT(sizeof(RingGenState) == 0xc);

typedef struct IMSpaceRingInterfaceVTable
{
    void* pad00[9];
    int (*isVisible)(GameObject* ring);
} IMSpaceRingInterfaceVTable;

STATIC_ASSERT(offsetof(IMSpaceRingInterfaceVTable, isVisible) == 0x24);

extern ObjectDescriptor gIMSpaceRingGenObjDescriptor;

int IMSpaceRingGen_getExtraSize(void);
int IMSpaceRingGen_getObjectTypeId(void);
void IMSpaceRingGen_free(GameObject* obj);
void IMSpaceRingGen_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void IMSpaceRingGen_hitDetect(void);
void IMSpaceRingGen_update(GameObject* obj);
void IMSpaceRingGen_init(GameObject* obj);
void IMSpaceRingGen_release(void);
void IMSpaceRingGen_initialise(void);

#endif
