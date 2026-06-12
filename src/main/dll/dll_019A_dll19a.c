#include "main/dll/dll_0198_nwshlevcon.h"
#include "main/dll/dll199state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"





/*
 * --INFO--
 *
 * Function: dll_197_init
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */






/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);













#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dimmagicbridge.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
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


/*
 * --INFO--
 *
 * Function: dll_199_update
 * EN v1.0 Address: 0x801CAD80
 * EN v1.0 Size: 2228b
 */


/*
 * --INFO--
 *
 * Function: dll_199_init
 * EN v1.0 Address: 0x801CB634
 * EN v1.0 Size: 364b
 */

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void Sfx_PlayFromObject(int obj, int sfx);

/*
 * --INFO--
 *
 * Function: dll_19A_update
 * EN v1.0 Address: 0x801CB7F0
 * EN v1.0 Size: 612b
 */
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
            *(s8*)(newObj + 0x2a) = *(s16*)obj >> 8;
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

/* Trivial 4b 0-arg blr leaves. */
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

/* 8b "li r3, N; blr" returners. */
int dll_19A_getExtraSize(void) { return 0x4; }
int dll_19A_getObjectTypeId(void) { return 0x0; }

void dll_19A_init(int obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    *(s16*)state = 100;
    ((Dll199State*)state)->unk2 = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5180;

void dll_19A_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5180);
}
