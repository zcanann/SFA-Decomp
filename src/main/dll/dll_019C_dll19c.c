/* DLL 0x19C - torch / flame controller objects [801CBA98-801CBD88) */
#include "main/dll/dll_019C_dll19c.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/resource.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/gamebit_ids.h"

typedef struct Dll19CPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 color[4];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x19 - 0x14];
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s8 rotXByte;
    s8 unk1F;
} Dll19CPlacement;

/* type id of the child object dll_19C_update spawns once its gate bit + spawn timer elapse */
#define DLL19C_CHILD_OBJ 0x248

int dll_19C_getExtraSize(void) { return 0x8; }
int dll_19C_getObjectTypeId(void) { return 0x0; }

void dll_19C_free(void)
{
}

void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void dll_19C_hitDetect(void)
{
}

void dll_19C_update(int* obj)
{

    u8* def;
    u8* sub;
    void* res;
    ObjPlacement* setup;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF8 != 0)
    {
        if (mainGetBit(0x1d4) != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
        }
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (mainGetBit(GAMEBIT_WM_KrazTest1TorchesActive) != 0)
        {
            res = Resource_Acquire(0x82, 1);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 0, 0, 1, -1, 0);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 1, -1, 0);
            Sfx_PlayFromObject(0, SFXTRIG_hitpos_6);
            Resource_Release(res);
            ((Dll19CState*)sub)->active = 1;
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    if (((Dll19CState*)sub)->active != 0)
    {
        ((Dll19CState*)sub)->spawnTimer = (s16)(((Dll19CState*)sub)->spawnTimer - ((Dll19CState*)sub)->active * framesThisStep);
    }
    if (((Dll19CState*)sub)->spawnTimer <= 0 && ((Dll19CPlacement*)def)->unk1F == 0 && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x18, DLL19C_CHILD_OBJ);
        setup->posX = ((Dll19CPlacement*)def)->posX;
        setup->posY = 50.0f + ((Dll19CPlacement*)def)->posY;
        setup->posZ = ((Dll19CPlacement*)def)->posZ;
        setup->objectId = DLL19C_CHILD_OBJ;
        setup->mapId = -1;
        setup->color[0] = ((Dll19CPlacement*)def)->color[0];
        setup->color[1] = ((Dll19CPlacement*)def)->color[1];
        setup->color[2] = ((Dll19CPlacement*)def)->color[2];
        setup->color[3] = ((Dll19CPlacement*)def)->color[3];
        Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, ((GameObject*)obj)->anim.parent);
        ((Dll19CState*)sub)->spawnTimer = 0x64;
        ((Dll19CState*)sub)->active = 0;
    }
}

void dll_19C_init(GameObject *obj, u8* initData)
{
    register int self = (int)obj;
    register int state = *(int*)&((GameObject*)self)->extra;
    *(short*)self = (short)((int)((Dll19CPlacement*)initData)->rotXByte << 8);
    ((GameObject*)self)->unkF8 = 0;
    ((Dll19CState*)state)->spawnTimer = 0x64;
    ((Dll19CState*)state)->active = 0;
    *(int*)state = 0;
    *(u8*)(self + 0x37) = 0xff;
    ((GameObject*)self)->anim.alpha = 0xff;
}

void dll_19C_release(void)
{
}

void dll_19C_initialise(void)
{
}
