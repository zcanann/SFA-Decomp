#include "main/dll/dll199state_struct.h"

extern void objRenderFn_8003b8f4(f32);

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/resource.h"

typedef struct Dll19APlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x1F - 0x8];
    s8 unk1F;
} Dll19APlacement;

extern u32 GameBit_Get(int eventId);

extern byte framesThisStep;

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void Sfx_PlayFromObject(int obj, int sfx);

extern f32 lbl_803E5180;

void dll_19A_update(int obj)
{
    int setup;
    short* state;
    int* res;
    int newObj;
    char* r;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x5b9) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        *state = 100;
        state[1] = 0;
        *(u8*)(obj + 0x37) = 0xff;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    else
    {
        if ((((GameObject*)obj)->unkF8 == 0) && (GameBit_Get(((Dll19APlacement*)setup)->unk1F + 0x1cd) != 0))
        {
            res = Resource_Acquire(0x82, 1);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 1, 0, 1, 0xffffffff, 0);
            Sfx_PlayFromObject(obj, 0xaf);
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
            newObj = Obj_AllocObjectSetup(0x38, 0x2d0);
            *(f32*)(newObj + 8) = ((ObjPlacement*)setup)->posX;
            *(f32*)(newObj + 0xc) = ((ObjPlacement*)setup)->posY;
            *(f32*)(newObj + 0x10) = ((ObjPlacement*)setup)->posZ;
            *(u8*)(newObj + 4) = ((Dll19APlacement*)setup)->unk4;
            *(u8*)(newObj + 5) = ((Dll19APlacement*)setup)->unk5;
            *(u8*)(newObj + 6) = ((Dll19APlacement*)setup)->unk6;
            *(u8*)(newObj + 7) = ((Dll19APlacement*)setup)->unk7;
            *(u8*)(newObj + 0x27) = 1;
            *(s16*)(newObj + 0x18) = 0x1e7;
            *(s16*)(newObj + 0x30) = 0xffff;
            *(s8*)(newObj + 0x2a) = ((GameObject*)obj)->anim.rotX >> 8;
            *(u8*)(newObj + 0x2b) = 2;
            if (GameBit_Get(0x1ce) != 0)
            {
                *(s16*)(newObj + 0x22) = 0x49;
            }
            else
            {
                *(s16*)(newObj + 0x22) = 0xffff;
            }
            *(u8*)(newObj + 0x29) = 0xff;
            *(s8*)(newObj + 0x2e) = -1;
            {
                int linkIdx = ((Dll19APlacement*)setup)->unk1F;
                *(u8*)(newObj + 0x32) = linkIdx;
            }
            r = Obj_SetupObject(newObj, 5, ((GameObject*)obj)->anim.mapEventSlot, 0xffffffff,
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

void dll_199_release(void);

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
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}

void dll_19A_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5180);
}
