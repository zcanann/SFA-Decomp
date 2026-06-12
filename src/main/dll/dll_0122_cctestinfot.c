/* === moved from main/dll/CF/dll_166.c [8018ADB4-8018ADF0) (TU re-split, docs/boundary_audit.md) === */
#include "main/objseq.h"

extern void* Obj_GetPlayerObject(void);





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




/* 8b "li r3, N; blr" returners. */
int cctestinfot_getExtraSize(void) { return 0x8; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void trickyguardspot_free(TrickyGuardSpotObject* obj);

extern void objSetHintTextIdx(int obj, int idx);



void cctestinfot_init(int obj, s8* def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *(s16*)obj = (s16)((s32)(u8)def[0x1A] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;
extern f32 lbl_803E3C88;
extern f32 lbl_803E3C8C;

void cctestinfot_update(int* obj)
{
    extern void*Obj_GetPlayerObject(void);
    u8* sub = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if (sub[4] != 0)
    {
        if (playerIsDisguised() == 0)
        {
            sub[4] = 0;
        }
    }
    else
    {
        if (playerIsDisguised() != 0)
        {
            sub[4] = 1;
        }
    }
    objSetHintTextIdx((int)obj, sub[4]);
    Obj_SetActiveModelIndex(obj, sub[4]);
    if (ObjTrigger_IsSet((int)obj) != 0 && fn_801334E0() == 0)
    {
        *(f32*)sub = lbl_803E3C88;
    }
    if (*(f32*)sub > lbl_803E3C8C)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) == 0)
        {
            *(f32*)sub = lbl_803E3C8C;
        }
        else
        {
            *(f32*)sub = *(f32*)sub - timeDelta;
            showHelpText(((s16*)((char*)*(int**)&((GameObject*)obj)->anim.modelInstance + 0x7c))[sub[4]]);
        }
    }
}

extern int Obj_GetActiveModel(int* obj);










