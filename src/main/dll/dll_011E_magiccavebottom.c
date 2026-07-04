/* DLL 0x011E (magiccavebottom) — Magic Cave bottom area objects [0x8018ADB4-0x8018AFC8). */
#include "main/objseq.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/player_80295318_shared.h"
#include "main/audio/music_trigger_ids.h"
extern int ObjTrigger_IsSet();
extern void objRenderFn_80041018(int obj);
extern void envFxActFn_800887f8(u8 value);
extern void getEnvfxAct(int* obj, int* target, int id, int p);

extern void warpToMap(int idx, s8 transType);

#define MAGICCAVEBOTTOM_GAMEBIT_ACTIVE 0xefb /* bottom-area loaded/active latch */
#define MAGICCAVE_GAMEBIT_WARP_READY 0x91e   /* handoff to top: perform warp sequence */
#define MAGICCAVE_GAMEBIT_WARP_DEST 0x1b8    /* warp destination map index */

/* magiccavebottom_update sequence state machine (state byte at extra[0]) */
#define MAGICCAVEBOTTOM_STATE_SETUP 0     /* latch active, seed env fx, run intro seq */
#define MAGICCAVEBOTTOM_STATE_START_MUSIC 1 /* kick off the adventure music */
#define MAGICCAVEBOTTOM_STATE_IDLE 2      /* show prompt, wait for the player trigger */
#define MAGICCAVEBOTTOM_STATE_WARP 3      /* latch warp-ready and warp to the destination */

int magiccavebottom_getExtraSize(void)
{
    return 1;
}

void magiccavebottom_free(int obj)
{


    (void)obj;
    GameBit_Set(MAGICCAVEBOTTOM_GAMEBIT_ACTIVE, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure, 0);
}


void magiccavebottom_update(int* obj)
{


    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* sub = ((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    switch (*sub)
    {
    case MAGICCAVEBOTTOM_STATE_SETUP:
        GameBit_Set(MAGICCAVEBOTTOM_GAMEBIT_ACTIVE, 1);
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x2c, 0);
        getEnvfxAct(obj, obj, 0x2d, 0);
        *sub = MAGICCAVEBOTTOM_STATE_START_MUSIC;
        if (def[0x1b] != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        }
        break;
    case MAGICCAVEBOTTOM_STATE_START_MUSIC:
        Music_Trigger(MUSICTRIG_PU3_Adventure, 1);
        *sub = MAGICCAVEBOTTOM_STATE_IDLE;
        break;
    case MAGICCAVEBOTTOM_STATE_IDLE:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x19);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            *sub = MAGICCAVEBOTTOM_STATE_WARP;
            if (def[0x1b] != 0)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(3, obj, -1);
            }
        }
        else
        {
            objRenderFn_80041018((int)obj);
        }
        break;
    case MAGICCAVEBOTTOM_STATE_WARP:
        GameBit_Set(MAGICCAVE_GAMEBIT_WARP_READY, 1);
        warpToMap(GameBit_Get(MAGICCAVE_GAMEBIT_WARP_DEST), 0);
        break;
    }
}
