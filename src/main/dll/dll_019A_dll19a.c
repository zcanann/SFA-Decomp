#include "main/dll/dimmagicbridge.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/resource.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/foodbag.h"

/* 0x38-byte spawn descriptor handed to Obj_SetupObject for the child
 * object (type 0x2d0). ObjPlacement-style head (color/position) plus
 * class-specific tail. */
typedef struct Dll19ASpawnSetup
{
    ObjPlacement base;
    s16 unk18;    /* 0x18 */
    u8 pad1A[8];  /* 0x1a */
    s16 unk22;    /* 0x22 */
    u8 pad24[3];  /* 0x24 */
    u8 unk27;     /* 0x27 */
    u8 pad28;     /* 0x28 */
    u8 unk29;     /* 0x29 */
    s8 rotX;      /* 0x2a: anim.rotX >> 8 */
    u8 unk2B;     /* 0x2b */
    u8 pad2C[2];  /* 0x2c */
    s8 unk2E;     /* 0x2e */
    u8 pad2F;     /* 0x2f */
    s16 unk30;    /* 0x30 */
    u8 linkIndex; /* 0x32: placement gateBitIndex forwarded as child link index */
    u8 pad33[5];  /* 0x33 */
} Dll19ASpawnSetup;

STATIC_ASSERT(offsetof(Dll19ASpawnSetup, base.posX) == 0x8);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, rotX) == 0x2a);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, linkIndex) == 0x32);
STATIC_ASSERT(sizeof(Dll19ASpawnSetup) == 0x38);

#define GAMEBIT_DLL19A_RESET     0x5b9
#define GAMEBIT_DLL19A_GATE_BASE 0x1cd

/* type id of the child object spawned into a Dll19ASpawnSetup once the gate bit + timer elapse */
#define DLL19A_CHILD_OBJ 0x2d0

extern f32 lbl_803E5180;

int dll_19A_getExtraSize(void)
{
    return sizeof(Dll19AState);
}
int dll_19A_getObjectTypeId(void)
{
    return 0x0;
}

void dll_19A_free(void)
{
}

void dll_19A_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E5180);
}

void dll_19A_hitDetect(void)
{
}

void dll_19A_update(GameObject* obj)
{
    Dll19APlacement* placement;
    Dll19AState* state;
    Dll82Interface** res;
    Dll19ASpawnSetup* newObj;
    GameObject* r;

    placement = (Dll19APlacement*)obj->anim.placementData;
    state = obj->extra;
    if (mainGetBit(GAMEBIT_DLL19A_RESET) != 0)
    {
        obj->userData2 = 0;
        state->countdown = 100;
        state->countdownRate = 0;
        obj->anim.pad37[0] = 0xff;
        obj->anim.alpha = 0xff;
    }
    else
    {
        if ((obj->userData2 == 0) &&
            (mainGetBit(placement->gateBitIndex + GAMEBIT_DLL19A_GATE_BASE) != 0))
        {
            res = Resource_Acquire(0x82, 1);
            (*res)->spawn(obj, 0, NULL, 1, -1, NULL);
            (*res)->spawn(obj, 1, NULL, 1, -1, NULL);
            Sfx_PlayFromObject((int)obj, SFXTRIG_hitpos_6);
            Resource_Release(res);
            state->countdownRate = 1;
            obj->userData2 = 1;
        }
        if (state->countdownRate != 0)
        {
            state->countdown -= state->countdownRate * framesThisStep;
        }
        if ((state->countdown <= 0) && (Obj_IsLoadingLocked() != 0))
        {
            newObj = (Dll19ASpawnSetup*)Obj_AllocObjectSetup(sizeof(Dll19ASpawnSetup), DLL19A_CHILD_OBJ);
            newObj->base.posX = placement->base.posX;
            newObj->base.posY = placement->base.posY;
            newObj->base.posZ = placement->base.posZ;
            newObj->base.color[0] = placement->base.color[0];
            newObj->base.color[1] = placement->base.color[1];
            newObj->base.color[2] = placement->base.color[2];
            newObj->base.color[3] = placement->base.color[3];
            newObj->unk27 = 1;
            newObj->unk18 = 0x1e7;
            newObj->unk30 = 0xffff;
            newObj->rotX = obj->anim.rotX >> 8;
            newObj->unk2B = 2;
            if (mainGetBit(GAMEBIT_DLL19A_GATE_BASE + 1) != 0)
            {
                newObj->unk22 = 0x49;
            }
            else
            {
                newObj->unk22 = 0xffff;
            }
            newObj->unk29 = 0xff;
            newObj->unk2E = -1;
            {
                int linkIdx = placement->gateBitIndex;
                newObj->linkIndex = linkIdx;
            }
            r = Obj_SetupObject(&newObj->base, 5, obj->anim.mapEventSlot, 0xffffffff, obj->anim.parent);
            if ((r != NULL) && (r->extra != NULL))
            {
                *(u8*)((u8*)r->extra + 0x404) = 0x20;
            }
            state->countdown = 100;
            state->countdownRate = 0;
        }
    }
}

void dll_19A_init(GameObject* obj, Dll19APlacement* placement)
{
    Dll19AState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->rotX << 8);
    obj->userData2 = 0;
    state->countdown = 100;
    state->countdownRate = 0;
    obj->anim.pad37[0] = 0xFF;
    obj->anim.alpha = 0xFF;
}

void dll_19A_release(void)
{
}

void dll_19A_initialise(void)
{
}

ObjectDescriptor dll_19A = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_19A_initialise,
    (ObjectDescriptorCallback)dll_19A_release,
    0,
    (ObjectDescriptorCallback)dll_19A_init,
    (ObjectDescriptorCallback)dll_19A_update,
    (ObjectDescriptorCallback)dll_19A_hitDetect,
    (ObjectDescriptorCallback)dll_19A_render,
    (ObjectDescriptorCallback)dll_19A_free,
    (ObjectDescriptorCallback)dll_19A_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_19A_getExtraSize,
};
