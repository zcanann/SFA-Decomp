#include "main/obj_placement.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/resource.h"

extern void objRenderFn_8003b8f4(f32 scale);
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);

typedef struct DfshShrinePlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 startDelay;
    u8 pad1C[0x24 - 0x1C];
} DfshShrinePlacement;

STATIC_ASSERT(sizeof(DfshShrinePlacement) == 0x24);
STATIC_ASSERT(offsetof(DfshShrinePlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DfshShrinePlacement, startDelay) == 0x1A);

extern f32 lbl_803E4EB8;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int objectId);
extern void* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, int parent);
extern ModgfxInterface** gModgfxInterface;

void dfsh_objcreator_free(void)
{
}

void dfsh_objcreator_hitDetect(void)
{
}

int SpiritPrize_getExtraSize(void);
int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4EB8);
}

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

/* segment pragma-stack balance (re-split): */

typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

void dfsh_objcreator_update(int obj)
{
    extern uint GameBit_Get(int eventId);
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    void* resource;
    u8* spawnSetup;

    if (GameBit_Get(0x589) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        return;
    }

    if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get((s8)setup[0x1f] + 0xf6) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 0, 0, 1, -1, 0);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, SFXsc_gemrun1022);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        ((GameObject*)obj)->unkF8 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer =
            (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = Obj_AllocObjectSetup(0x38, 0x11);
        *(f32*)(spawnSetup + 0x08) = ((ObjPlacement*)setup)->posX;
        *(f32*)(spawnSetup + 0x0c) = ((ObjPlacement*)setup)->posY;
        *(f32*)(spawnSetup + 0x10) = ((ObjPlacement*)setup)->posZ;
        *(int*)(spawnSetup + 0x14) = ((ObjPlacement*)setup)->mapId;
        spawnSetup[0x04] = setup[0x04];
        spawnSetup[0x05] = setup[0x05];
        spawnSetup[0x06] = setup[0x06];
        spawnSetup[0x07] = setup[0x07];
        spawnSetup[0x27] = 3;
        *(s16*)(spawnSetup + 0x18) = 0x1e7;
        *(s16*)(spawnSetup + 0x30) = -1;
        *(s16*)(spawnSetup + 0x1a) = -1;
        *(s16*)(spawnSetup + 0x1c) = -1;
        *(s8*)(spawnSetup + 0x2a) = (s8)(*(s16*)obj >> 8);
        spawnSetup[0x2b] = 2;
        if (GameBit_Get(0xfc) != 0)
        {
            *(s16*)(spawnSetup + 0x22) = 0x49;
        }
        else
        {
            *(s16*)(spawnSetup + 0x22) = -1;
        }
        spawnSetup[0x29] = 0xff;
        *(s8*)(spawnSetup + 0x2e) = -1;
        *(u16*)(spawnSetup + 0x34) = 0xffff;
        Obj_SetupObject(spawnSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        *(int*)&((GameObject*)obj)->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

void dfsh_objcreator_release(void)
{
}

void dfsh_objcreator_initialise(void)
{
}

void dfsh_objcreator_init(int obj, s8* def)
{
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}
