/* DLL 0x011E (magiccavebottom) — Magic Cave bottom area objects [0x8018ADB4-0x8018AFC8). */
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern ObjectTriggerInterface** gObjectTriggerInterface;





/*
 * --INFO--
 *
 * Function: treasurechest_update
 * EN v1.0 Address: 0x8018AA60
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x8018AA94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: treasurechest_release
 * EN v1.0 Address: 0x8018ADB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AF9C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: treasurechest_initialise
 * EN v1.0 Address: 0x8018ADB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AFA0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: magiccavebottom_getExtraSize
 * EN v1.0 Address: 0x8018ADBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018AFA4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int magiccavebottom_getExtraSize(void)
{
    return 1;
}

void magiccavebottom_free(int obj)
{
    extern void Music_Trigger(s32 triggerId, s32 mode);
    extern void GameBit_Set(int eventId, int value);
    (void)obj;
    GameBit_Set(0xefb, 0);
    Music_Trigger(0x2f, 0);
}

void treasurechest_init(int* obj);

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/camera_interface.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"









extern int ObjTrigger_IsSet();



/*
 * --INFO--
 *
 * Function: FUN_8018af28
 * EN v1.0 Address: 0x8018AF28
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8018AF64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018b220
 * EN v1.0 Address: 0x8018B220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018B230
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018b224
 * EN v1.0 Address: 0x8018B224
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8018B314
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off

extern void objRenderFn_80041018(int obj);



/* 8b "li r3, N; blr" returners. */

/* ObjGroup_RemoveObject(x, N) wrappers. */











extern void envFxActFn_800887f8(int a);
extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void setAButtonIcon(int idx);
extern void warpToMap(int mapId, int b);

void magiccavebottom_update(int* obj)
{
    extern void Music_Trigger(int a, int b);
    extern undefined8 GameBit_Set(int eventId, int value);
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* sub = ((GameObject*)obj)->extra;

    *(s16*)obj = (s16)((s32)def[0x1a] << 8);
    switch (*sub)
    {
    case 0:
        GameBit_Set(0xefb, 1);
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x2c, 0);
        getEnvfxAct(obj, obj, 0x2d, 0);
        *sub = 1;
        if (def[0x1b] != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        }
        break;
    case 1:
        Music_Trigger(0x2f, 1);
        *sub = 2;
        break;
    case 2:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
        {
            setAButtonIcon(0x19);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            *sub = 3;
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
    case 3:
        GameBit_Set(0x91e, 1);
        warpToMap(GameBit_Get(0x1b8), 0);
        break;
    }
}

extern f32 lbl_803E3C80;




