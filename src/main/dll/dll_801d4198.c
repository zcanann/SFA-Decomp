#include "main/dll/SH/dll_01A9_bombplant.h"

extern void* Obj_GetPlayerObject(void);

#include "main/game_object.h"
#include "main/dll/SH/dll_01AC_shqueenearthwalker.h"

extern void Sfx_StopObjectChannel(void* obj, int channel);
extern int fn_8003B500(void* obj, void* p2, f32 f1);
extern int fn_8003B228(void* obj, void* p2);
extern int characterDoEyeAnims(void* obj, void* p2);

extern f32 lbl_803E53F8;

int sh_queenearthwalker_processAnimEvents(void* obj, void* unused, ObjAnimUpdateState* animUpdate)
{
    void* pState = ((GameObject*)obj)->extra;
    int i;
    u8 b2;

    if ((((QueenEarthWalkerState*)pState)->flags & 0x20) == 0)
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        ((QueenEarthWalkerState*)pState)->flags &= ~0x10;
        ((QueenEarthWalkerState*)pState)->flags |= 0x20;
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 0:
            ((QueenEarthWalkerState*)pState)->flags |= 0x8;
            break;
        case 1:
            ((QueenEarthWalkerState*)pState)->flags &= ~0x8;
            break;
        case 2:
            ((QueenEarthWalkerState*)pState)->flags |= 0x2;
            break;
        case 3:
            ((QueenEarthWalkerState*)pState)->flags &= ~0x2;
            animUpdate->hitVolumePair |= 0x8;
            animUpdate->hitVolumePair |= 0x40;
            break;
        }
    }

    b2 = ((QueenEarthWalkerState*)pState)->flags;
    if ((b2 & 0x2) != 0)
    {
        if ((b2 & 0x4) == 0)
        {
            void* player;
            animUpdate->hitVolumePair &= ~0x8;
            player = Obj_GetPlayerObject();
            *(u8*)((int)pState + 0x8) = 1;
            ((QueenEarthWalkerState*)pState)->targetX = ((GameObject*)player)->anim.localPosX;
            ((QueenEarthWalkerState*)pState)->targetY = ((GameObject*)player)->anim.localPosY;
            ((QueenEarthWalkerState*)pState)->targetZ = ((GameObject*)player)->anim.localPosZ;
            fn_8003B500(obj, (u8*)pState + 0x8, lbl_803E53F8);
        }
        animUpdate->hitVolumePair &= ~0x40;
        if ((((QueenEarthWalkerState*)pState)->flags & 0x8) != 0)
        {
            fn_8003B228(obj, (u8*)pState + 0x8);
        }
        else
        {
            characterDoEyeAnims(obj, (u8*)pState + 0x8);
        }
    }
    return 0;
}
