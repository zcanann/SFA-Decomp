#include "main/dll/dll_0198_nwshlevcon.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern undefined4 FUN_8003b818();

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E5150;
extern void objRenderFn_8003b8f4(f32);
extern void Music_Trigger(int track, int param);
extern int GameBit_Set(int eventId, int value);
extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern ModgfxInterface** gModgfxInterface;
extern void* Obj_GetPlayerObject(void);
extern void fn_80296518(void* player, int a, int b);

void FUN_801cacd4(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void nwsh_levcon_hitDetect(void)
{
}

void nwsh_levcon_release(void)
{
}

void nwsh_levcon_initialise(void)
{
}

int nwsh_levcon_getExtraSize(void) { return 0x0; }
int nwsh_levcon_getObjectTypeId(void) { return 0x0; }

void nwsh_levcon_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5150);
}

void nwsh_levcon_free(int obj)
{
    Music_Trigger(6, 0);
    GameBit_Set(3837, 0);
}

void nwsh_levcon_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(0, 0, 0xd1, 0);
            getEnvfxAct(0, 0, 0xd6, 0);
            getEnvfxAct(0, 0, 0x222, 0);
        }
    }
}

void nwsh_levcon_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(6, 1);
    ((GameObject*)obj)->unkF4 = 1;
    GameBit_Set(0xea2, 1);
    GameBit_Set(0xefd, 1);
}

int NWSH_levcon_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    void* player;
    int i;

    player = Obj_GetPlayerObject();
    if (player != 0)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            switch (animUpdate->eventIds[i])
            {
            case 1:
                fn_80296518(player, 0x10, 1);
                GameBit_Set(0x174, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 4, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1d, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1e, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1f, 1);
                (*gMapEventInterface)->setMapAct(0xb, 6);
                break;
            default:
                break;
            }
        }
    }
    return 0;
}

int dll_199_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);
