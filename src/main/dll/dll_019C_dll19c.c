/* DLL 0x19C — torch / flame controller objects [801CBA98-801CBD88) */
#include "main/dll/dll19cstate_struct.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/resource.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

typedef struct Dll19CPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x19 - 0x14];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} Dll19CPlacement;

extern f32 lbl_803E51B0;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);

extern f32 lbl_803E51B4;

void dll_19C_free(void)
{
}

void dll_19C_hitDetect(void)
{
}

void dll_19C_release(void)
{
}

void dll_19C_initialise(void)
{
}


int dll_19C_getExtraSize(void) { return 0x8; }
int dll_19C_getObjectTypeId(void) { return 0x0; }

void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E51B0);
}

void dll_19C_update(int* obj)
{

    u8* def;
    u8* sub;
    void* res;
    void* setup;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF8 != 0)
    {
        if (GameBit_Get(0x1d4) != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
        }
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (GameBit_Get(0x1d3) != 0)
        {
            res = Resource_Acquire(0x82, 1);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 0, 0, 1, -1, 0);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 1, -1, 0);
            Sfx_PlayFromObject(0, SFXsc_gemrun1022);
            Resource_Release(res);
            ((Dll19CState*)sub)->active = 1;
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    if (((Dll19CState*)sub)->active != 0)
    {
        ((Dll19CState*)sub)->spawnTimer = (s16)(((Dll19CState*)sub)->spawnTimer - ((Dll19CState*)sub)->active * framesThisStep);
    }
    if (((Dll19CState*)sub)->spawnTimer <= 0 && (s8)def[0x1f] == 0 && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x18, 0x248);
        ((ObjPlacement*)setup)->posX = ((Dll19CPlacement*)def)->posX;
        ((ObjPlacement*)setup)->posY = lbl_803E51B4 + ((Dll19CPlacement*)def)->posY;
        ((ObjPlacement*)setup)->posZ = ((Dll19CPlacement*)def)->posZ;
        *(s16*)setup = 0x248;
        ((ObjPlacement*)setup)->mapId = -1;
        *(u8*)((char*)setup + 4) = def[4];
        *(u8*)((char*)setup + 5) = def[5];
        *(u8*)((char*)setup + 6) = def[6];
        *(u8*)((char*)setup + 7) = def[7];
        Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(void**)&((GameObject*)obj)->anim.parent);
        ((Dll19CState*)sub)->spawnTimer = 0x64;
        ((Dll19CState*)sub)->active = 0;
    }
}


/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
void dll_19C_init(int obj, u8* initData)
{
    register int self = obj;
    register int state = *(int*)&((GameObject*)self)->extra;
    *(short*)self = (short)((int)(signed char)initData[0x1e] << 8);
    ((GameObject*)self)->unkF8 = 0;
    ((Dll19CState*)state)->spawnTimer = 0x64;
    ((Dll19CState*)state)->active = 0;
    *(int*)state = 0;
    *(u8*)(self + 0x37) = 0xff;
    ((GameObject*)self)->anim.alpha = 0xff;
}

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */
void dll_19D_free(int obj);

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
