/*
 * DLL 0x219 - a game-bit gated sliding object.
 *
 * Only the object with id DLL_219_MOVING_OBJECT_ID is animated; the
 * remaining ids are inert (update returns immediately). When its game
 * bit is set the object slides its world X down to
 * (placement posX - 30) at speed 0.4; when the bit
 * is clear it slides back up to placement posX at speed 0.2,
 * clamping at each end. init seeds the object's rotX and the state's
 * game bit from the placement record; free releases its expgfx source.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

#define DLL_219_MOVING_OBJECT_ID 0x3a6
#define DLL_219_INERT_OBJECT_ID_LO 0x3ad
#define DLL_219_INERT_OBJECT_ID_HI 0x3ae

#define DLL_219_OBJFLAG_HIDDEN 0x4000
#define DLL_219_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct Dll219State
{
    s16 gameBit;
} Dll219State;

typedef struct Dll219Setup
{
    ObjPlacement placement;
    s8 rotX;        /* 0x18 */
    u8 pad19[0x1e - 0x19];
    s16 gameBit;    /* 0x1e */
} Dll219Setup;

typedef struct Dll219Object
{
    u8 pad00[0xc];
    f32 x;              /* 0x0c: current world X */
    u8 pad10[0x46 - 0x10];
    s16 objectId;       /* 0x46 */
    u8 pad48[0x4c - 0x48];
    ObjPlacement* setup; /* 0x4c */
    u8 pad50[0xb8 - 0x50];
    Dll219State* state; /* 0xb8 */
} Dll219Object;

int dll_219_getExtraSize_ret_4(void) { return 0x4; }

int dll_219_getObjectTypeId(void) { return 0x0; }

void dll_219_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_219_render_nop(void)
{
}

void dll_219_hitDetect_nop(void)
{
}

void dll_219_update(Dll219Object* obj)
{
    ObjPlacement* setup = obj->setup;
    Dll219State* state = obj->state;
    s16 objectId = obj->objectId;

    switch (objectId)
    {
    case DLL_219_MOVING_OBJECT_ID:
        break;
    case DLL_219_INERT_OBJECT_ID_LO:
    case DLL_219_INERT_OBJECT_ID_HI:
    default:
        return;
    }

    if (GameBit_Get(state->gameBit) != 0)
    {
        if (obj->x > setup->posX - 30.0f)
        {
            obj->x -= 0.4f;
            if (obj->x < setup->posX - 30.0f)
            {
                obj->x = setup->posX - 30.0f;
            }
            return;
        }
    }
    if (GameBit_Get(state->gameBit) == 0)
    {
        if (obj->x < setup->posX)
        {
            obj->x += 0.2f;
            if (obj->x > setup->posX)
            {
                obj->x = setup->posX;
            }
        }
    }
}

void dll_219_init(int* obj, Dll219Setup* placement)
{
    Dll219State* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotX << 8);
    state->gameBit = placement->gameBit;
    ((GameObject*)obj)->objectFlags |= (DLL_219_OBJFLAG_HIDDEN | DLL_219_OBJFLAG_HITDETECT_DISABLED);
}

void dll_219_release_nop(void)
{
}

void dll_219_initialise_nop(void)
{
}
