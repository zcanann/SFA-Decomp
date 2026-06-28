/*
 * sh_queenearthwalker anim-event processor (DLL 0x1AC, Queen
 * EarthWalker boss). animEventCallback installed by
 * sh_queenearthwalker_init; runs each animation tick to drive the
 * boss's attack/feed behaviour from sequence event ids:
 *   0/1  enable/disable the "do eye anims" branch
 *   2/3  enter/leave the targeting state (flag 0x2); event 3 also
 *        arms two hit-volume pair bits
 * While targeting (flag 0x2), the boss latches the player position
 * once (flag 0x4) and either runs the bite (fn_8003B228) or the eye
 * tracking (characterDoEyeAnims) depending on flag 0x8. Flag 0x20 is
 * a one-shot init guard that stops the looping SFX on channel 0x7f.
 */
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/SH/dll_01AC_shqueenearthwalker.h"

/* QueenEarthWalkerState::flags bits */
#define QEW_FLAG_EYE_ANIMS 0x8  /* run characterDoEyeAnims vs the bite */
#define QEW_FLAG_TARGETING 0x2  /* targeting the player */
#define QEW_FLAG_LATCHED 0x4    /* player position captured; set/cleared by SH/dll_01AC_shqueenearthwalker.c */
#define QEW_FLAG_INIT_DONE 0x20 /* one-shot init guard */
#define QEW_FLAG_ACTIVE 0x10    /* feed sequence completed; suppress idle attacks */

extern void* Obj_GetPlayerObject(void);
extern void Sfx_StopObjectChannel(void* obj, int channel);
extern int fn_8003B500(void* obj, void* p2, f32 f1);
extern int fn_8003B228(void* obj, void* p2);
extern int characterDoEyeAnims(void* obj, void* p2);

extern f32 lbl_803E53F8; /* .sdata2 const, shared with SH/dll_01AC_shqueenearthwalker.c */

int sh_queenearthwalker_processAnimEvents(void* obj, void* unused, ObjAnimUpdateState* animUpdate)
{
    QueenEarthWalkerState* state = ((GameObject*)obj)->extra;
    int i;
    u8 flags;

    if ((state->flags & QEW_FLAG_INIT_DONE) == 0)
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        state->flags &= ~QEW_FLAG_ACTIVE;
        state->flags |= QEW_FLAG_INIT_DONE;
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 0:
            state->flags |= QEW_FLAG_EYE_ANIMS;
            break;
        case 1:
            state->flags &= ~QEW_FLAG_EYE_ANIMS;
            break;
        case 2:
            state->flags |= QEW_FLAG_TARGETING;
            break;
        case 3:
            state->flags &= ~QEW_FLAG_TARGETING;
            animUpdate->hitVolumePair |= 0x8;
            animUpdate->hitVolumePair |= 0x40;
            break;
        }
    }

    flags = state->flags;
    if ((flags & QEW_FLAG_TARGETING) != 0)
    {
        if ((flags & QEW_FLAG_LATCHED) == 0)
        {
            GameObject* player;
            animUpdate->hitVolumePair &= ~0x8;
            player = Obj_GetPlayerObject();
            ((QueenEarthWalkerState*)state)->eyeAnimEnabled = 1;
            state->targetX = player->anim.localPosX;
            state->targetY = player->anim.localPosY;
            state->targetZ = player->anim.localPosZ;
            fn_8003B500(obj, (u8*)state + 0x8, lbl_803E53F8);
        }
        animUpdate->hitVolumePair &= ~0x40;
        if ((state->flags & QEW_FLAG_EYE_ANIMS) != 0)
        {
            fn_8003B228(obj, (u8*)state + 0x8);
        }
        else
        {
            characterDoEyeAnims(obj, (u8*)state + 0x8);
        }
    }
    return 0;
}
