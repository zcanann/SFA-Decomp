#include "main/game_object.h"

extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern void objRenderFn_8003b8f4(f32);

extern f32 lbl_803E54C8;

extern s32 lbl_803DC058[2];
extern void getYButtonItem(s16 * out);
extern int cMenuGetSelectedItem(void);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);

void warpstonelift_free(void)
{
}

void warpstonelift_hitDetect(void)
{
}

void warpstonelift_release(void)
{
}

void warpstonelift_initialise(void)
{
}

int warpstonelift_getExtraSize(void) { return 0x1; }
int warpstonelift_getObjectTypeId(void) { return 0x0; }
int sh_staff_getExtraSize(void);

void warpstonelift_init(int obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    int i;
    *(s16*)obj = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->unkF4 = 0;
    for (i = 0; i < 2; i++)
    {
        if (GameBit_Get(lbl_803DC058[i]) != 0)
        {
            *(u8*)state = (u8)(i + 1);
        }
    }
    switch (*(u8*)state)
    {
    case 0:
    case 2:
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
        break;
    case 1:
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        break;
    }
}

void warpstonelift_update(u8* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    int off;
    char* p;
    int found = 0;
    int count;
    int i;
    s16 item;

    p = *(char**)(obj + 0x58);
    count = *(s8*)(p + 0x10F);
    if (count > 0)
    {
        off = 0;
        for (i = 0; i < count; i++)
        {
            char* o = *(char**)((int)p + (off + 0x100));
            if (((GameObject*)o)->anim.classId == 1)
            {
                found = 1;
            }
            off += 4;
        }
    }
    if (found)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        switch (*state)
        {
        case 0:
        case 1:
            getYButtonItem(&item);
            if ((GameBit_Get(0xC7C) != 0 && cMenuGetSelectedItem() != -1) || item == 0xC7C)
            {
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
            }
            else
            {
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
            }
            if (ObjTrigger_IsSetById((int)obj, 0xC7C) != 0)
            {
                GameBit_Set(0x886, 1);
                GameBit_Set(0xC7D, 1);
                *state = 2;
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
            }
            else if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0xC7E, 1);
            }
            break;
        case 2:
            if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0x886, 1);
            }
            break;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
    }
}

void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E54C8);
}

void sh_staff_free(int* obj, int p2);
