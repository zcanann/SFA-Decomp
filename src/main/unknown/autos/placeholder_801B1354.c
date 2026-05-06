#include "ghidra_import.h"

extern u8 *ObjList_FindObjectById(int objectId);

typedef struct DimSnowballState {
    void *target;
    int targetId;
} DimSnowballState;

typedef struct DimSnowballObject {
    u8 unk0[0x54];
    u8 *handle54;
    u8 unk58[0xc];
    u8 *handle64;
    u8 unk68[0x48];
    u16 flags;
    u8 unkB2[6];
    DimSnowballState *state;
} DimSnowballObject;

typedef struct DimSnowballDef {
    u8 unk0[0x14];
    int targetId;
} DimSnowballDef;

void dimsnowball_init(DimSnowballObject *obj, DimSnowballDef *def)
{
    DimSnowballState *state;

    state = obj->state;
    state->targetId = def->targetId;
    def->targetId = -1;
    state->target = ObjList_FindObjectById(state->targetId);
    if (obj->handle54 != NULL) {
        obj->handle54[0x6a] = 0;
    }
    if (obj->handle64 != NULL) {
        *(u32 *)(obj->handle64 + 0x30) |= 0x810;
    }
    obj->flags |= 0x4000;
}

void dimsnowball_release(void)
{
}

void dimsnowball_initialise(void)
{
}

int dimsnowball1c2_getExtraSize(void)
{
    return 4;
}
