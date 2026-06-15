#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_01A1_nwmammoth.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/dll/creator1D4.h"
#include "main/dll/dim2conveyor.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/gameplay_runtime.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/curve.h"
#include "main/sky_interface.h"
#include "main/dll/player_target.h"

extern uint GameBit_Get(int eventId);
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 objAudioFn_8006ef38();
extern uint countLeadingZeros();

extern undefined4 DAT_803274f4;
extern f64 DOUBLE_803e5eb8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5E98;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;
extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;
extern f32 lbl_803E5ECC;
extern f32 lbl_803E5ED0;

#pragma scheduling on
#pragma peephole on
extern f32 timeDelta;
extern f32 lbl_803E520C;
extern f32 lbl_803E5218;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E523C;
extern f32 lbl_803E5240;
extern f32 lbl_803E5244;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;
extern f32 lbl_803E5250;
extern int lbl_803DBF80;
extern int lbl_803DBF84;
extern int lbl_803DBF88;
extern int lbl_803DBF8C;
extern int lbl_803DBF90;
extern int lbl_803DBF94;
extern int lbl_803DBF98;
extern int lbl_803DBF9C;
extern int lbl_803DBFA0;
extern int lbl_803DBFA4;
extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E5228;
extern f32 lbl_803E522C;
extern f32 lbl_803E5230;
extern f32 lbl_803E5234;
extern f32 lbl_803E5238;
extern int lbl_803DBFA8;
extern int lbl_803DBFAC;
extern int lbl_803DBFB0;
extern int lbl_803268CC[];
extern int lbl_803268DC[];
extern int* ObjList_FindObjectById(int id);
extern void fn_8014C66C(int* o, int* target);
extern int* tumbleweedbush_findNearestActive(void* pos);
extern f32 getXZDistance(void* a, void* b);
extern void fn_80163980(int o);
extern void Obj_FreeObject(int o);
extern f32 lbl_803E5210;
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSetById();
extern void fn_8003A168(int obj, void* p);
extern void characterDoEyeAnims(int obj, void* p);
extern int cMenuGetSelectedItem(void);
extern void fn_801CDF94(int obj, void* state, int flag);
extern u8 lbl_803267C0[];
extern u8 lbl_803267E8[];
extern u8 lbl_80326818[];
extern ObjHitReactEntry DAT_80327400;
extern ObjHitReactEntry DAT_80327414;
extern undefined4 DAT_80327468;
extern undefined4 DAT_80327498;
extern NwMammothPathControlInterface** gPathControlInterface;
extern u32 lbl_803E5208;
extern f32 lbl_803E5254;
extern f32 lbl_803E5258;

void FUN_801ce078(undefined2* param_1, int param_2)
{
}

void FUN_801ce340(short* param_1, int param_2, int param_3)
{
    if (((param_3 == 0) || (*(int*)(param_2 + 0x28) == 0)) ||
        (lbl_803E5EAC <= *(float*)(param_2 + 0x18)))
    {
        *(undefined*)(param_2 + 0x40c) = 0;
    }
    else
    {
        *(undefined*)(param_2 + 0x40c) = 1;
        *(undefined4*)(param_2 + 0x410) = *(undefined4*)(*(int*)(param_2 + 0x28) + 0xc);
        *(undefined4*)(param_2 + 0x414) = *(undefined4*)(*(int*)(param_2 + 0x28) + 0x10);
        *(undefined4*)(param_2 + 0x418) = *(undefined4*)(*(int*)(param_2 + 0x28) + 0x14);
    }
    if (((&DAT_803274f4)[*(byte*)(param_2 + 0x408)] & 2) == 0)
    {
        fn_8003A328((double)lbl_803E5EA4, param_1, (char*)(param_2 + 0x40c));
        FUN_8003b280((int)param_1, param_2 + 0x40c);
    }
    else
    {
        FUN_8003a1c4((int)param_1, param_2 + 0x40c);
        FUN_8003b1a4((int)param_1, param_2 + 0x40c);
    }
    return;
}

int nw_mammoth_getExtraSize(void)
{
    return 0x48c;
}

#pragma scheduling off
#pragma peephole off
void fn_801CEE0C(int p1, int p2)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern int fn_801CE078(int);
    extern int ObjTrigger_IsSetById(int, int);
    extern int gameBitDecrement(int);
    extern int lbl_803DBF70;
    extern int lbl_803DBF74;
    extern int lbl_803DBF78;
    extern int lbl_803DBF7C;

    if (fn_801CE078(p1) != 0) return;

    switch (*(u8*)(p2 + 0x408))
    {
    case 0:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBF70;
        if (GameBit_Get(211) != 0)
        {
            *(u8*)(p2 + 0x408) = 1;
        }
        break;
    case 1:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBF74;
        {
            switch (GameBit_Get(1400))
            {
            case 0:
                if (ObjTrigger_IsSetById(p1, 1398) != 0)
                {
                    GameBit_Set(1400, 1);
                    gameBitDecrement(1398);
                    (*gObjectTriggerInterface)->runSequence(2, (void*)p1, -1);
                    *(u8*)(p2 + 0x43c) = (u8)(*(u8*)(p2 + 0x43c) | 0x10);
                    *(u8*)(p2 + 0x408) = 2;
                }
                break;
            case 1:
                *(u8*)(p2 + 0x408) = 2;
                break;
            default:
                *(u8*)(p2 + 0x408) = 3;
                break;
            }
        }
        break;
    case 2:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBF78;
        if (ObjTrigger_IsSetById(p1, 1398) != 0)
        {
            GameBit_Set(1400, 2);
            gameBitDecrement(1398);
            (*gObjectTriggerInterface)->runSequence(4, (void*)p1, -1);
            *(u8*)(p2 + 0x408) = 3;
            *(u8*)(p2 + 0x43c) = (u8)(*(u8*)(p2 + 0x43c) | 0x10);
        }
        break;
    case 3:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBF7C;
        break;
    }
}

void fn_801CED2C(int p1, int p2)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern int ObjTrigger_IsSetById(int, int);
    extern int lbl_803DBFB4;
    extern int lbl_803DBFB8;
    extern int lbl_803DBFBC;

    switch (*(u8*)(p2 + 0x408))
    {
    case 4:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBFB4;
        if (ObjTrigger_IsSetById(p1, 418) != 0)
        {
            *(u8*)(p2 + 0x43c) = (u8)(*(u8*)(p2 + 0x43c) | 0x10);
            GameBit_Set(413, 1);
            GameBit_Set(419, 1);
            GameBit_Set(3813, 1);
            GameBit_Set(3814, 1);
            *(u8*)(p2 + 0x408) = 5;
        }
        break;
    case 5:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBFB8;
        if (GameBit_Get(415) != 0)
        {
            *(u8*)(p2 + 0x408) = 6;
        }
        break;
    case 6:
        *(int*)(p2 + 0x48) = (int)&lbl_803DBFBC;
        break;
    }
}

typedef struct
{
    u8 pad[0xc];
    f32 pos[3];
} WoPartfxBlock;

int fn_801CE078(int* obj, u8* st)
{
    extern u32 randomGetRange(int min, int max); /* #57 */
    u8 cv;
    int snd;
    f32 sunTime;
    WoPartfxBlock blk;

    cv = (u8)(*gSkyInterface)->getSunPosition(&sunTime);
    if (*(s8*)(st + 0x45b) != 0)
    {
        snd = !*(s8*)(st + 0x453);
    }
    else
    {
        snd = 0;
    }
    if (st[0x408] < 0x14)
    {
        if (cv != 0)
        {
            if (*(f32*)(st + 0x54) > lbl_803E520C)
            {
                return -1;
            }
            st[0x409] = st[0x408];
            st[0x408] = 0x14;
        }
        else
        {
            return 0;
        }
    }
    switch (st[0x408])
    {
    case 0x14:
        if (snd != 0)
        {
            Sfx_PlayFromObject((u32)obj, 0x14b);
        }
        if (st[0x43c] & 2)
        {
            st[0x408] = 0x15;
            *(f32*)(st + 4) = (f32)(s32)
            randomGetRange(0, 300);
        }
        break;
    case 0x15:
        if (snd != 0)
        {
            Sfx_PlayFromObject((u32)obj, 0x14c);
        }
        *(f32*)(st + 4) -= timeDelta;
        if (cv == 0 && *(f32*)(st + 4) <= lbl_803E520C)
        {
            st[0x408] = 0x16;
        }
        {
            f32 t = *(f32*)(st + 0x1c) - timeDelta;
            *(f32*)(st + 0x1c) = t;
            if (t <= lbl_803E520C)
            {
                if (((GameObject*)obj)->objectFlags & 0x800)
                {
                    blk.pos[0] = *(f32*)(st + 0xc);
                    blk.pos[1] = *(f32*)(st + 0x10);
                    blk.pos[2] = *(f32*)(st + 0x14);
                    (*gPartfxInterface)->spawnObject(obj, 0x7f0, &blk, 0x200001, -1, NULL);
                }
                *(f32*)(st + 0x1c) = lbl_803E5218;
            }
        }
        break;
    case 0x16:
        if (snd != 0)
        {
            Sfx_PlayFromObject((u32)obj, 0x14d);
        }
        if (st[0x43c] & 2)
        {
            st[0x408] = st[0x409];
        }
        break;
    }
    return 1;
}

void fn_801CEA14(short* obj, u8* st, u8* p3)
{
    switch (fn_801CE078((int*)obj, st))
    {
    case -1:
        *(f32*)(st + 0x54) -= lbl_803E523C * timeDelta;
        if (*(f32*)(st + 0x54) < lbl_803E5240)
        {
            *(f32*)(st + 0x54) = lbl_803E520C;
        }
        break;
    case 0:
        if ((*((u8*)obj + 0xaf) & 4) || *(f32*)(st + 0x18) < lbl_803E5244)
        {
            *(f32*)(st + 0x54) -= lbl_803E5248 * timeDelta;
            if (*(f32*)(st + 0x54) < lbl_803E5240)
            {
                *(f32*)(st + 0x54) = lbl_803E520C;
            }
        }
        else
        {
            *(f32*)(st + 0x54) += lbl_803E523C * timeDelta;
            if (*(f32*)(st + 0x54) > lbl_803E524C)
            {
                *(f32*)(st + 0x54) = *(f32*)&lbl_803E524C;
            }
        }
        break;
    case 1:
        return;
    }
    switch (st[0x408])
    {
    case 8:
        {
            u8* cv = st + 0x5c;
            if (Curve_AdvanceAlongPath((Curve*)cv, *(f32*)(st + 0x54)) != 0 || *(int*)(cv + 0x10) != 0)
            {
                (*gRomCurveInterface)->goNextPoint(cv);
            }
            {
                f32 dx = *(f32*)(cv + 0x68) - ((GameObject*)obj)->anim.localPosX;
                f32 dz = *(f32*)(cv + 0x70) - ((GameObject*)obj)->anim.localPosZ;
                ObjAnim_SampleRootCurvePhase(oneOverTimeDelta * sqrtf(dx * dx + dz * dz),
                                             (ObjAnimComponent*)obj, (float*)(st + 0x4c));
            }
            ((GameObject*)obj)->anim.rotX = (s16)(getAngle(*(f32*)(cv + 0x74), *(f32*)(cv + 0x7c)) + 0x8000);
            ((GameObject*)obj)->anim.localPosX = *(f32*)(cv + 0x68);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)(cv + 0x70);
            if (*(f32*)(st + 0x54) <= lbl_803E520C)
            {
                st[0x408] = 7;
            }
            break;
        }
    case 7:
        if (*(f32*)(st + 0x54) > lbl_803E5250)
        {
            st[0x408] = 8;
        }
        break;
    }
    if (*(s8*)(p3 + 0x1d) == 1)
    {
        if (GameBit_Get(0x19d) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF90;
        }
        else if (GameBit_Get(0x1a2) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF8C;
        }
        else if (GameBit_Get(0x102) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF88;
        }
        else if (GameBit_Get(0x9e) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF84;
        }
        else
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF80;
        }
    }
    else
    {
        if (GameBit_Get(0x19d) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBFA4;
        }
        else if (GameBit_Get(0x1a2) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBFA0;
        }
        else if (GameBit_Get(0x102) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF9C;
        }
        else if (GameBit_Get(0x9e) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF98;
        }
        else
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBF94;
        }
    }
}

void fn_801CE2BC(int* obj, u8* st, short* p3)
{
    extern f32 vec3f_distanceSquared(void* a, void* b); /* #57 */
    extern int* getTrickyObject(void); /* #57 */
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    int near_ = ObjGroup_FindNearestObject(0xf, obj, 0);
    switch (st[0x408])
    {
    case 9:
        *(f32*)(st + 0) += timeDelta;
        if (*(f32*)(st + 0) > lbl_803E5228)
        {
            Sfx_PlayFromObject((u32)obj, 0x150);
            *(f32*)(st + 0) -= lbl_803E5228;
        }
        if (*(f32*)(st + 0x18) < (f32)(s32)(p3[0xc] * p3[0xc]))
        {
            st[0x408] = 0xa;
        }
        break;
    case 0xa:
        if (st[0x43c] & 2)
        {
            st[0x408] = 0xb;
        }
        break;
    case 0xb:
        *(f32*)(st + 0) += timeDelta;
        if (*(f32*)(st + 0) > lbl_803E5228)
        {
            Sfx_PlayFromObject((u32)obj, 0x150);
            *(f32*)(st + 0) -= lbl_803E5228;
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(3, (void*)near_, -1);
            st[0x43c] = (u8)(st[0x43c] | 0x10);
            st[0x408] = 0xd;
            GameBit_Set(0xce1, 1);
            GameBit_Set(0xd32, 1);
        }
        break;
    case 0xc:
        (*gObjectTriggerInterface)->preempt(near_, 0x5aa);
        (*gObjectTriggerInterface)->runSequence(3, (void*)near_, 0x30);
        st[0x408] = 0xd;
        break;
    case 0xd:
        {
            int n = 4;
            if (GameBit_Get(0x120) == 0)
            {
                n = 3;
            }
            if (GameBit_Get(0x121) == 0)
            {
                n -= 1;
            }
            {
                int i = 0;
                int* gb = lbl_803268DC;
                int* ids = lbl_803268CC;
                for (; i < n; i++)
                {
                    if (GameBit_Get(*gb) != 0)
                    {
                        GameBit_Set(*gb, 0);
                    }
                    {
                        int* o2 = ObjList_FindObjectById(*ids);
                        if ((int*)Player_GetTargetObject(*(int*)(st + 0x28)) == o2)
                        {
                            fn_8014C66C(o2, *(int**)(st + 0x28));
                        }
                        else
                        {
                            int* tw = tumbleweedbush_findNearestActive((char*)o2 + 0x18);
                            if (tw == NULL || vec3f_distanceSquared((char*)tw + 0x18, (char*)o2 + 0x18) >= lbl_803E522C)
                            {
                                if (vec3f_distanceSquared(*(char**)(st + 0x28) + 0x18, (char*)o2 + 0x18) >=
                                    lbl_803E522C)
                                {
                                    fn_8014C66C(o2, obj);
                                }
                                else
                                {
                                    fn_8014C66C(o2, *(int**)(st + 0x28));
                                }
                            }
                            else
                            {
                                fn_8014C66C(o2, tw);
                            }
                        }
                    }
                    gb++;
                    ids++;
                }
            }
            {
                int* tw2 = tumbleweedbush_findNearestActive(st + 0xc);
                if (tw2 != NULL)
                {
                    int* tk = getTrickyObject();
                    (**(void (**)(int*, int*, int, int))((char*)(*(int**)*(int*)((char*)tk + 0x68)) + 0x28))(
                        tk, obj, 1, 1);
                }
                *(int*)(st + 0x48) = (int)&lbl_803DBFA8;
                if (*(void**)(st + 0x24) == NULL)
                {
                    short* cfg = *(short**)&((GameObject*)obj)->anim.placementData;
                    if (tw2 != NULL && *(s16*)((char*)tw2 + 0x46) == 0x3fb)
                    {
                        if (getXZDistance((char*)obj + 0x18, (char*)tw2 + 0x18) < (f32)(s32)(cfg[0xc] * cfg[0xc]))
                        {
                            if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                            {
                                Sfx_PlayFromObject((u32)obj, 0x38a);
                            }
                            if ((**(int (**)(int*))((char*)(*(int**)*(int*)((char*)tw2 + 0x68)) + 0x30))(tw2) == 0)
                            {
                                (**(void (**)(int*, u8*))((char*)(*(int**)*(int*)((char*)tw2 + 0x68)) + 0x2c))(
                                    tw2, st + 0xc);
                                *(int**)(st + 0x24) = tw2;
                                st[0x408] = 0xe;
                            }
                        }
                    }
                }
            }
            if (!(st[0x43c] & 0x40))
            {
                (*gGameUIInterface)->initAirMeter(0xc8, 0x5d0);
                st[0x43c] = (u8)(st[0x43c] | 0x40);
            }
            break;
        }
    case 0xe:
        if (getXZDistance(st + 0xc, *(char**)(st + 0x24) + 0x18) < lbl_803E5230)
        {
            Sfx_PlayFromObject((u32)obj, 0x38b);
            fn_80163980(*(int*)(st + 0x24));
            st[0x408] = 0xf;
        }
        break;
    case 0xf:
        if (st[0x43c] & 2)
        {
            Obj_FreeObject(*(int*)(st + 0x24));
            *(int*)(st + 0x24) = 0;
            *(s8*)(st + 0x43f) += 1;
            if (*(s8*)(st + 0x43f) > 3)
            {
                *(s8*)(st + 0x43f) = 3;
            }
            GameBit_Set(0x48b, *(s8*)(st + 0x43f));
            if (*(s8*)(st + 0x43f) >= 3)
            {
                st[0x408] = 0x11;
            }
            else
            {
                if (*(s8*)(st + 0x43f) % 2 == 0)
                {
                    Sfx_PlayFromObject((u32)obj, 0x14f);
                }
                st[0x408] = 0xd;
            }
        }
        break;
    case 0x10:
        (*gObjectTriggerInterface)->preempt(near_, 0x157c);
        (*gObjectTriggerInterface)->runSequence(1, (void*)near_, 2);
        st[0x408] = 0x13;
        break;
    case 0x11:
        if (!(*(u16*)(*(char**)(st + 0x28) + 0xb0) & 0x1000) && *(f32*)(st + 8) >= lbl_803E5234)
        {
            Sfx_PlayFromObject((u32)obj, 0x109);
            (*gScreenTransitionInterface)->start(0x14, 1);
            st[0x408] = 0x12;
            GameBit_Set(0xd32, 0);
            st[0x43c] = (u8)(st[0x43c] & ~0x40);
            (*gGameUIInterface)->airMeterShutdown();
        }
        break;
    case 0x12:
        if (!(*(u16*)(*(char**)(st + 0x28) + 0xb0) & 0x1000))
        {
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                GameBit_Set(0x102, 1);
                (*gObjectTriggerInterface)->runSequence(1, (void*)near_, -1);
                st[0x408] = 0x13;
            }
        }
        break;
    case 0x13:
    default:
        if (GameBit_Get(0x224) != 0)
        {
            *(int*)(st + 0x48) = (int)&lbl_803DBFB0;
        }
        else
        {
            if (GameBit_Get(0xea7) == 0)
            {
                GameBit_Set(0xea7, 1);
                GameBit_Set(0x9d5, 1);
            }
            *(int*)(st + 0x48) = (int)&lbl_803DBFAC;
        }
        fn_801CE078(obj, st);
        break;
    }
    if (st[0x43c] & 0x40)
    {
        if (*(f32*)(st + 8) < lbl_803E5238 * (f32) * (s8*)(st + 0x43f))
        {
            *(f32*)(st + 8) += timeDelta;
        }
        if (*(f32*)(st + 8) >= lbl_803E5234)
        {
            (*gGameUIInterface)->runAirMeter(0xc8);
        }
        else
        {
            (*gGameUIInterface)->runAirMeter((int)*(f32*)(st + 8));
        }
    }
}

/* segment pragma-stack balance (re-split): */

void nw_mammoth_free(void* obj)
{
    extern void ObjGroup_RemoveObject(void* obj, int group); /* #57 */
    void* node;

    node = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x4d);
    if ((*((u8*)node + 0x43c) & 0x40) != 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
}

void nw_mammoth_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    extern void ObjPath_GetPointWorldPosition(void* obj, int idx, void* out0, void* out1, void* out2, int flag); /* #57 */
    extern void objRenderFn_8003b8f4(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale); /* #57 */
    int i;
    void* node;

    node = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5210);
    for (i = 0; i < 4; i++)
    {
        ObjPath_GetPointWorldPosition(obj, i,
                                      (char*)node + i * 0xc + 0x45c,
                                      (char*)node + i * 0xc + 0x460,
                                      (char*)node + i * 0xc + 0x464,
                                      0);
    }
    ObjPath_GetPointWorldPosition(obj, 4,
                                  (char*)node + 0xc,
                                  (char*)node + 0x10,
                                  (char*)node + 0x14,
                                  0);
}

#define gNwMammothNormalHitReactEntry DAT_80327400
#define gNwMammothHeavyHitReactEntry DAT_80327414
#define gNwMammothStateMoveIds DAT_80327468
#define gNwMammothStateMoveStepScales DAT_80327498
#define gNwMammothStateFlags DAT_803274f4

#define NW_MAMMOTH_STATE_FLAGS(table) ((u8 *)((table) + 0xf4))
#define NW_MAMMOTH_MOVE_IDS(table) ((s16 *)((table) + 0x68))
#define NW_MAMMOTH_MOVE_STEP_SCALES(table) ((f32 *)((table) + 0x98))
#define NW_MAMMOTH_HIT_REACT_ENTRIES(table) ((ObjHitReactEntry *)(table))
#define NW_MAMMOTH_HEAVY_HIT_REACT_ENTRIES(table) \
  ((ObjHitReactEntry *)((table) + sizeof(ObjHitReactEntry)))
#define NW_MAMMOTH_HIT_REACT_STEP_SCALE(state) ((f32 *)((state) + 0x50))
#define NW_MAMMOTH_HIT_REACT_STATE(state) ((state)[0x3d4])

enum NwMammothStateFlag
{
    NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
    NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
    NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
    NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
    NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

enum NwMammothRuntimeFlag
{
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};

void nw_mammoth_update(NwMammothObject* obj, int param_2)
{
    extern void fn_801CE2BC(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CEA14(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CED2C(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CEE0C(int obj, void* state, void* objDef); /* #57 */
    extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2); /* #57 */
    extern u32 randomGetRange(int min, int max); /* #57 */
    NwMammothTables* table = (NwMammothTables*)lbl_803267C0;
    NwMammothState* state;
    NwMammothMapData* mapData;
    u8 stateIndex;
    u8 stateFlags;
    ObjHitReactEntry* hitReactEntries;
    int currentMove;
    f32 stepScale;
    int triggerIndex;

    (void)param_2;
    state = obj->state;
    mapData = obj->mapData;
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_RESET_PATH) != 0)
    {
        state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_RESET_PATH);
    }
    state->playerObject = Obj_GetPlayerObject();
    if (state->playerObject == NULL)
    {
        return;
    }
    stateIndex = state->stateIndex;
    stateFlags = table->stateFlags[stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SOLID) != 0)
    {
        obj->objectFlags = (u16)(obj->objectFlags | NW_MAMMOTH_SOLID_OBJECT_FLAG);
        obj->modelState->flags = obj->modelState->flags & ~(u64)NW_MAMMOTH_MODEL_COLLISION_FLAG;
    }
    else
    {
        obj->objectFlags = (u16)(obj->objectFlags & ~NW_MAMMOTH_SOLID_OBJECT_FLAG);
        obj->modelState->flags = obj->modelState->flags | NW_MAMMOTH_MODEL_COLLISION_FLAG;
    }
    stateFlags = table->stateFlags[state->stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT) == 0)
    {
        if ((stateFlags & NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT) != 0)
        {
            hitReactEntries = &table->heavyHitReactEntry;
        }
        else
        {
            hitReactEntries = &table->normalHitReactEntry;
        }
        state->hitReactState =
            ObjHitReact_Update((int)obj, hitReactEntries, 1, state->hitReactState,
                               &state->hitReactStepScale);
        if (state->hitReactState != 0)
        {
            fn_8003A168((int)obj, state->eyeAnimState);
            characterDoEyeAnims((int)obj, state->eyeAnimState);
            return;
        }
    }
    state->playerDistanceSq = vec3f_distanceSquared(&obj->worldPosX,
                                                    &((NwMammothObject*)state->playerObject)->worldPosX);
    switch (mapData->behaviorMode)
    {
    case 0:
        fn_801CEE0C((int)obj, state, mapData);
        break;
    case 2:
        fn_801CED2C((int)obj, state, mapData);
        break;
    case 1:
    case 3:
        fn_801CEA14((int)obj, state, mapData);
        break;
    case 4:
        fn_801CE2BC((int)obj, state, mapData);
        break;
    }
    stateFlags = table->stateFlags[state->stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_PATH_CONTROL) != 0)
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags | NW_MAMMOTH_PATH_CONTROL_FLAG);
    }
    else
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags & ~NW_MAMMOTH_PATH_CONTROL_FLAG);
        if (((stateFlags & NW_MAMMOTH_STATE_FLAG_MENU_ACTION) != 0) &&
            (cMenuGetSelectedItem() != -1))
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        }
        else
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
        }
    }
    stateIndex = state->stateIndex;
    currentMove = table->stateMoveIds[stateIndex];
    if (obj->currentMove != currentMove)
    {
        stepScale = table->stateMoveStepScales[stateIndex];
        if (stepScale > lbl_803E520C)
        {
            ObjAnim_SetCurrentMove((int)obj, currentMove, lbl_803E520C, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, currentMove, lbl_803E5210, 0);
        }
        state->animStepScale = table->stateMoveStepScales[state->stateIndex];
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, state->animStepScale, timeDelta,
                                                                    &state->animEvents) != 0)
    {
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    else
    {
        state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    objAudioFn_8006ef38((int)obj, &state->animEvents, 8, state->pathPoints, state->pathState,
                        lbl_803E5210, *(f32*)&lbl_803E5210);
    fn_801CDF94((int)obj, state, table->stateFlags[state->stateIndex] & 4);
    state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
    if (((state->runtimeFlags & NW_MAMMOTH_RUNTIME_MENU_LOCK) == 0) && (ObjTrigger_IsSet((int)obj) != 0))
    {
        triggerIndex = randomGetRange(NW_MAMMOTH_TRIGGER_RANDOM_MIN, *state->triggerList);
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
        (*gObjectTriggerInterface)->runSequence(state->triggerList[triggerIndex], obj, -1);
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0)
    {
        (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
        (*gPathControlInterface)->apply(obj, state->pathState);
        (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
    }
}

void nw_mammoth_init(NwMammothObject* obj, NwMammothMapData* mapData, int isReload)
{
    u32 pathParam;
    NwMammothState* state;
    int curveParam;

    state = obj->state;
    pathParam = lbl_803E5208;
    obj->rotX = (s16)(mapData->modelIndex << 8);
    obj->seqCallback = nw_mammoth_SeqFn;
    if (isReload != 0)
    {
        return;
    }
    state->animStepScale = lbl_803E5258;
    switch (mapData->behaviorMode)
    {
    case 0:
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        break;
    case 2:
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        if (GameBit_Get(0x19f) != 0)
        {
            state->stateIndex = 6;
        }
        else if (GameBit_Get(0x19d) != 0)
        {
            state->stateIndex = 5;
        }
        else
        {
            state->stateIndex = 4;
        }
        break;
    case 1:
    case 3:
        curveParam = NW_MAMMOTH_CURVE_PARAM;
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        if ((u8)(*gRomCurveInterface)->initCurve(
            &state->curveState, obj, lbl_803E5254, &curveParam, -1) == 0)
        {
            obj->localPosX = state->curveState.pointX;
            obj->localPosZ = state->curveState.pointZ;
            state->stateIndex = 8;
            state->pathSpeed = lbl_803E524C;
        }
        break;
    case 4:
        state->uiMessageCount = (s8)GameBit_Get(0x48b);
        if (GameBit_Get(0x102) != 0)
        {
            state->stateIndex = 0x10;
        }
        else if (GameBit_Get(0xce1) != 0)
        {
            state->stateIndex = 0xc;
            if (state->uiMessageCount >= 3)
            {
                ((NwMammothGameUiInterface*)*gGameUIInterface)->showMessage(NW_MAMMOTH_UI_MESSAGE_ID, NW_MAMMOTH_UI_MESSAGE_TEXT_ID);
                state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE);
                state->stateIndex = 0x11;
            }
        }
        else
        {
            state->stateIndex = 9;
        }
        break;
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0)
    {
        u8* path = state->pathState;
        (*gPathControlInterface)->init(path, 3, 2, 1);
        (*gPathControlInterface)->setup(path, NW_MAMMOTH_PATH_SETUP_POINT_COUNT,
                                        lbl_803267E8, lbl_80326818, &pathParam);
        (*gPathControlInterface)->attachObject(obj, path);
    }
    ObjGroup_AddObject(obj, NW_MAMMOTH_GROUP_ID);
}

int nw_tricky_SeqFn(void);

void nw_tricky_free(int obj);
