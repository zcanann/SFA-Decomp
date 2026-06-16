#include "main/dll/VF/vf_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

extern const f32 lbl_803E60A8;
extern f32 lbl_803E60AC;
extern f32 lbl_803E60B0;

#define DLL_219_MOVING_OBJECT_ID 0x3a6
#define DLL_219_OBJECT_ID_GATE 0x3ad
#define DLL_219_UNUSED_OBJECT_ID 0x3af

typedef struct Dll219State
{
    s16 gameBit;
} Dll219State;

typedef struct Dll219Object
{
    u8 pad00[0xc];
    f32 x;
    u8 pad10[0x46 - 0x10];
    s16 objectId;
    u8 pad48[0x4c - 0x48];
    u8* setup;
    u8 pad50[0xb8 - 0x50];
    Dll219State* state;
} Dll219Object;

int dll_219_getExtraSize_ret_4(void) { return 0x4; }

int dll_219_getObjectTypeId(void) { return 0x0; }

void dll_219_render_nop(void)
{
}

void dll_219_hitDetect_nop(void)
{
}

void dll_219_release_nop(void)
{
}

void dll_219_initialise_nop(void)
{
}

void dll_219_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_219_update(Dll219Object* obj)
{
    u8* setup = obj->setup;
    Dll219State* state = obj->state;
    s16 objectId = obj->objectId;

    if (objectId < DLL_219_OBJECT_ID_GATE)
    {
        if (objectId != DLL_219_MOVING_OBJECT_ID)
        {
            return;
        }
    }
    else
    {
        if (objectId == DLL_219_UNUSED_OBJECT_ID)
        {
            return;
        }
        return;
    }

    if ((u32)GameBit_Get(state->gameBit) != 0)
    {
        if (obj->x > ((ObjPlacement*)setup)->posX - lbl_803E60A8)
        {
            obj->x -= lbl_803E60AC;
            if (obj->x < ((ObjPlacement*)setup)->posX - lbl_803E60A8)
            {
                obj->x = ((ObjPlacement*)setup)->posX - lbl_803E60A8;
            }
            return;
        }
    }
    if ((u32)GameBit_Get(state->gameBit) == 0)
    {
        if (obj->x < ((ObjPlacement*)setup)->posX)
        {
            obj->x += lbl_803E60B0;
            if (obj->x > ((ObjPlacement*)setup)->posX)
            {
                obj->x = ((ObjPlacement*)setup)->posX;
            }
        }
    }
}

void dll_219_init(int* obj, u8* init)
{
    int* inner = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    *(s16*)inner = *(s16*)((char*)init + 0x1e);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}
