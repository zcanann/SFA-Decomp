/* === moved from main/dll/SH/SHkillermushroom.c [801D3378-801D383C) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01A9_bombplant.h"
#include "main/objseq.h"







extern void* Obj_GetPlayerObject(void);




/*
 * --INFO--
 *
 * Function: bombplantspore_getExtraSize
 * EN v1.0 Address: 0x801D3378
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: bombplantspore_free
 * EN v1.0 Address: 0x801D3380
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801D3970
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: bombplantspore_startDriftBurst
 * EN v1.0 Address: 0x801D33D4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Keep the cross-TU bl: these two drift helpers' only callers
 * (bombplantspore_update/init) live in the BombPlantSpore TU
 * (SHrocketmushroom.c). Once they land there, dont_inline stops MWCC
 * auto-inlining them into bombplantspore_update. */
#pragma dont_inline on

/*
 * --INFO--
 *
 * Function: bombplantspore_updateDrift
 * EN v1.0 Address: 0x801D359C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: bombplant_init
 * EN v1.0 Address: 0x801D3238
 * EN v1.0 Size: 320b
 */

/*
 * --INFO--
 *
 * Function: bombplant_update
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 1508b
 */

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/objseq.h"
#include "main/dll/SH/SHrocketmushroom.h"
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
