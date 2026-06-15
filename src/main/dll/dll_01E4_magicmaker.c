#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"

typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
} MagicmakerPlacement;

extern int randomGetRange(int min, int max);
extern void objRenderFn_8003b8f4(f32 scale);

extern u8 Obj_IsLoadingLocked(void);
extern void GameBit_Set(int eventId, int value);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern char* Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char* obj, f32 f, int a, int b, int c, int d);
extern u16 lbl_80325CE8[];
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

void magicmaker_free(void)
{
}

void magicmaker_hitDetect(void)
{
}

void magicmaker_init(void)
{
}

void magicmaker_release(void)
{
}

void magicmaker_initialise(void)
{
}

void dimbosscrackpar_hitDetect(void);

void magicmaker_update(int obj)
{
    int def;
    char* newobj;
    int n;
    int count;
    int* objs;
    int i;
    int j;
    char* setup;
    int o;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)GameBit_Get(0x26b) != 0u)
        {
            GameBit_Set(0x26b, 0);
            objs = ObjGroup_GetObjects(4, &count);
            n = 0;
            for (i = 0; i < count; i++)
            {
                o = *objs;
                for (j = 0; j < 6; j++)
                {
                    if (*(s16*)(o + 0x46) == lbl_80325CE8[j])
                    {
                        n++;
                    }
                }
                objs++;
            }
            if (n < 10)
            {
                setup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
                if (setup != NULL)
                {
                    *(u8*)(setup + 0x1a) = 0x14;
                    *(s16*)(setup + 0x2c) = -1;
                    *(s16*)(setup + 0x1c) = -1;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)setup)->posY = lbl_803E4D8C + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    *(s16*)(setup + 0x24) = -1;
                    *(u8*)(setup + 0x4) = ((MagicmakerPlacement*)def)->unk4;
                    *(u8*)(setup + 0x6) = ((MagicmakerPlacement*)def)->unk6;
                    *(u8*)(setup + 0x5) = ((MagicmakerPlacement*)def)->unk5;
                    *(u8*)(setup + 0x7) = ((MagicmakerPlacement*)def)->unk7;
                    *(s16*)(setup + 0x2e) = 3;
                    newobj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                             *(int*)&((GameObject*)obj)->anim.parent);
                    if (newobj != NULL)
                    {
                        i = 3;
                        do
                        {
                            hitDetectFn_80097070(newobj, lbl_803E4D88, 2, 2, 0x64, 0);
                            i--;
                        }
                        while (i != 0);
                    }
                }
            }
        }
    }
}

int magicmaker_getExtraSize(void) { return 0x0; }
int magicmaker_getObjectTypeId(void) { return 0x0; }
int dimbosscrackpar_getExtraSize(void);

void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4D88);
}
