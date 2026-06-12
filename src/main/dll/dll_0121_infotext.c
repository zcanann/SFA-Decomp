/* DLL 0x0121 — infotext. TU: 0x8018B9F0–0x8018BB00. */
#include "main/objseq.h"

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/camera_interface.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern int ObjTrigger_IsSet();

extern void objRenderFn_80041018(int obj);

int infotext_getExtraSize(void) { return 0x4; }
int cctestinfot_getExtraSize(void);

extern void objSetHintTextIdx(int obj, int idx);

void infotext_init(int obj, s8* def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *(s16*)obj = (s16)((s32)(u8)def[0x18] << 8);
    objSetHintTextIdx(obj, (int)(u8)def[0x19]);
}

void cctestinfot_init(int obj, s8* def);

extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;

extern f32 lbl_803E3C80;
extern f32 lbl_803E3C84;

void infotext_update(int obj)
{
    f32* sub = ((GameObject*)obj)->extra;
    if (ObjTrigger_IsSet(obj) != 0 && fn_801334E0() == 0)
    {
        *sub = lbl_803E3C80;
    }
    if (*sub > lbl_803E3C84)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) == 0)
        {
            *sub = lbl_803E3C84;
        }
        else
        {
            *sub = *sub - timeDelta;
            showHelpText(
                ((s16*)((char*)*(int**)&((GameObject*)obj)->anim.modelInstance + 0x7c))[(*(u8**)&((GameObject*)obj)->
                    anim.placementData)[0x19]]);
        }
    }
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0)
    {
        objRenderFn_80041018(obj);
    }
}

extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
