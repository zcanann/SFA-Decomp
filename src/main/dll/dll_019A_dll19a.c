#include "main/dll/dll199state_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct Dll19APlacement
{
    u8 pad0[0x4 - 0x0];
    u8 color[4]; /* 0x04: RGBA tint -> spawn setup color[4] */
    u8 pad8[0x1F - 0x8];
    s8 gateBitIndex; /* added to GAMEBIT_DLL19A_GATE_BASE; also passed to the child as link index */
} Dll19APlacement;

/* 0x38-byte spawn descriptor handed to Obj_SetupObject for the child
 * object (type 0x2d0). ObjPlacement-style head (color/position) plus
 * class-specific tail. */
typedef struct Dll19ASpawnSetup
{
    u8 pad00[4];   /* 0x00 */
    u8 color[4];   /* 0x04 */
    f32 posX;      /* 0x08 */
    f32 posY;      /* 0x0c */
    f32 posZ;      /* 0x10 */
    u8 pad14[4];   /* 0x14 */
    s16 unk18;     /* 0x18 */
    u8 pad1A[8];   /* 0x1a */
    s16 unk22;     /* 0x22 */
    u8 pad24[3];   /* 0x24 */
    u8 unk27;      /* 0x27 */
    u8 pad28;      /* 0x28 */
    u8 unk29;      /* 0x29 */
    s8 rotByte;    /* 0x2a: object yaw byte (anim.rotX >> 8) */
    u8 unk2B;      /* 0x2b */
    u8 pad2C[2];   /* 0x2c */
    s8 unk2E;      /* 0x2e */
    u8 pad2F;      /* 0x2f */
    s16 unk30;     /* 0x30 */
    u8 linkIndex;  /* 0x32: placement gateBitIndex forwarded as child link index */
    u8 pad33[5];   /* 0x33 */
} Dll19ASpawnSetup;

STATIC_ASSERT(offsetof(Dll19ASpawnSetup, posX) == 0x8);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, rotByte) == 0x2a);
STATIC_ASSERT(offsetof(Dll19ASpawnSetup, linkIndex) == 0x32);
STATIC_ASSERT(sizeof(Dll19ASpawnSetup) == 0x38);

#define GAMEBIT_DLL19A_RESET 0x5b9
#define GAMEBIT_DLL19A_GATE_BASE 0x1cd

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int typeId);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);

extern f32 lbl_803E5180;

void dll_19A_update(int obj)
{
    int setup;
    short* state;
    int* res;
    Dll19ASpawnSetup* newObj;
    char* r;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (GameBit_Get(GAMEBIT_DLL19A_RESET) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        *state = 100;
        state[1] = 0;
        *(u8*)(obj + 0x37) = 0xff; /* pad37[0], distinct from anim.alpha at 0x36 */
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    else
    {
        if ((((GameObject*)obj)->unkF8 == 0) && (GameBit_Get(((Dll19APlacement*)setup)->gateBitIndex + GAMEBIT_DLL19A_GATE_BASE) != 0))
        {
            res = Resource_Acquire(0x82, 1);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 1, 0, 1, 0xffffffff, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_hitpos_6);
            Resource_Release(res);
            state[1] = 1;
            ((GameObject*)obj)->unkF8 = 1;
        }
        if (state[1] != 0)
        {
            *state -= state[1] * framesThisStep;
        }
        if ((*state <= 0) && (Obj_IsLoadingLocked() != 0))
        {
            newObj = (Dll19ASpawnSetup*)Obj_AllocObjectSetup(0x38, 0x2d0);
            newObj->posX = ((ObjPlacement*)setup)->posX;
            newObj->posY = ((ObjPlacement*)setup)->posY;
            newObj->posZ = ((ObjPlacement*)setup)->posZ;
            newObj->color[0] = ((Dll19APlacement*)setup)->color[0];
            newObj->color[1] = ((Dll19APlacement*)setup)->color[1];
            newObj->color[2] = ((Dll19APlacement*)setup)->color[2];
            newObj->color[3] = ((Dll19APlacement*)setup)->color[3];
            newObj->unk27 = 1;
            newObj->unk18 = 0x1e7;
            newObj->unk30 = 0xffff;
            newObj->rotByte = ((GameObject*)obj)->anim.rotX >> 8;
            newObj->unk2B = 2;
            if (GameBit_Get(GAMEBIT_DLL19A_GATE_BASE + 1) != 0)
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
                int linkIdx = ((Dll19APlacement*)setup)->gateBitIndex;
                newObj->linkIndex = linkIdx;
            }
            r = Obj_SetupObject((int)newObj, 5, ((GameObject*)obj)->anim.mapEventSlot, 0xffffffff,
                                *(int*)&((GameObject*)obj)->anim.parent);
            if ((r != 0) && (((GameObject*)r)->extra != 0))
            {
                *(u8*)(*(int*)&((GameObject*)r)->extra + 0x404) = 0x20;
            }
            *state = 100;
            state[1] = 0;
        }
    }
}

void dll_19A_free(void)
{
}

void dll_19A_hitDetect(void)
{
}

void dll_19A_release(void)
{
}

void dll_19A_initialise(void)
{
}

int dll_19A_getExtraSize(void) { return 0x4; }
int dll_19A_getObjectTypeId(void) { return 0x0; }

void dll_19A_init(int obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    *(s16*)state = 100;
    ((Dll199State*)state)->unk2 = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF; /* pad37[0], distinct from anim.alpha at 0x36 */
    ((GameObject*)obj)->anim.alpha = 0xFF;
}

void dll_19A_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5180);
}
