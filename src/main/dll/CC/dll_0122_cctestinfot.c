
extern void* Obj_GetPlayerObject(void);

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern int ObjTrigger_IsSet();

extern void objSetHintTextIdx(int obj, int idx);
extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;
extern f32 lbl_803E3C88;
extern f32 lbl_803E3C8C;

int cctestinfot_getExtraSize(void) { return 0x8; }

void cctestinfot_init(int obj, s8* def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(u8)def[0x1A] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

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
            showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[sub[4]]);
        }
    }
}
