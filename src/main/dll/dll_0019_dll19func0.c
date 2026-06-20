/* DLL 0x0019 — dll19 / camDebug group. TU: 0x8010DB7C–0x8010DD58. */
#include "main/game_object.h"
#include "main/mm.h"
#include "main/objseq.h"
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

#include "main/camera_interface.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/mapEvent.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/player_status.h"
#include "main/dll/dll19_state.h"
#include "main/dll/baddie_state.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "string.h"
#include "main/object_transform.h"

typedef struct Dll19Placement
{
    u8 pad0[0x22 - 0x0];
    s16 stateFlags;
    u8 pad24[0x32 - 0x24];
    u8 progressDenominator;
    u8 pad33[0x3E8 - 0x33];
    f32 oscValue;
    f32 oscVelocity;
    u8 pad3F0[0x400 - 0x3F0];
    u16 flags;
    u8 pad402[0x408 - 0x402];
} Dll19Placement;

extern int FUN_80017730();
extern void* FUN_80017aa4();
extern u32 FUN_80017ae4();
extern u32 FUN_80017ae8();
extern void ObjHits_DisableObject(u32 objPtr);
extern void ObjHits_EnableObject(u32 objPtr);
extern int ObjHits_GetPriorityHitWithPosition();
extern u32 ObjGroup_FindNearestObject();
extern void ObjGroup_AddObject(u32 obj, int group);
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern u32 ObjMsg_AllocQueue();
extern u64 FUN_8028683c();
extern u32 FUN_80286888();
extern double FUN_80293900();
extern u32 FUN_80293f90();
extern u32 FUN_80294964();
extern u32 DAT_802c2910;
extern u32 DAT_802c2914;
extern u32 DAT_802c2918;
extern void** gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern float* DAT_803de1fc;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;

#pragma scheduling on
#pragma peephole on

extern f32 timeDelta;
extern void Sfx_StopObjectChannel(int* p1, int channel);
extern void voxmaps_freeRouteWork(void* p);
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern const f32 lbl_803E1C2C;
extern void ObjHits_SetHitVolumeSlot(void* obj, int animObjId, int frame, int flags);
extern void Obj_FreeObject(u8* obj);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern GameObject* Obj_SetupObject(ObjPlacement* setup, int mode, int mapLayer, int objIndex, int parent);
extern u8 lbl_802C2190[];
extern int* gPlayerInterface;
extern int Obj_GetPlayerObject(void);
extern int fn_80295A04(int obj, int sel);
extern f32 lbl_803E1C48;
extern const f32 lbl_803E1C6C;
extern f32 fn_8029610C(int obj);
extern void voxmaps_worldToGrid(f32* pos, int* grid);
extern f32 lbl_803E1C64;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E1C40;
extern f32 lbl_803E1C44;
extern f32 lbl_803E1C4C;
extern f32 lbl_803E1C50;
extern u32 lbl_803E1C18;
extern u32 lbl_803E1C1C;
extern u32 lbl_803E1C20;
extern u32 lbl_803E1C24;
extern f32 lbl_803E1C54;
extern f32 lbl_803E1C58;
extern const f32 lbl_803E1C5C;
extern f32 lbl_803E1C60;
extern GameObject* gDll19NearestObj;
extern void voxmaps_allocRouteWork(u8 * work);
extern u32 lbl_803E1C28;
extern u8 lbl_8031A054[];
extern u8 lbl_8031A048[];
extern u32 lbl_803DB9E0;
extern u32 lbl_803DD5E0;
extern void fn_8010DB7C(GameObject * target, f32 * a, f32 * b, f32 * c);
extern f32 lbl_803E1C78;
extern f32 lbl_803E1C7C;
extern void voxmaps_worldToGrid(f32* world, int* grid);
extern const f32 gDll19AnglePi;
extern const f32 gDll19BinaryAngleScale;
extern u8 framesThisStep;

void FUN_8010de18_v11_drift(u32 param_1, u32 param_2, float* param_3, float* param_4)
{
    float fVar1;
    float* pfVar2;
    int iVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    double dVar8;
    u64 uVar9;

    uVar9 = FUN_8028683c();
    pfVar2 = DAT_803de1fc;
    iVar3 = (int)((u64)uVar9 >> 0x20);
    dVar7 = (double)(*(float*)(iVar3 + 0x18) - *DAT_803de1fc);
    dVar5 = (double)(*(float*)(iVar3 + 0x20) - DAT_803de1fc[2]);
    dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar5 * dVar5)));
    FUN_80017730();
    dVar8 = (double)((float)(dVar7 * (double)DAT_803de1fc[0x11]) + *pfVar2);
    dVar6 = (double)((float)(dVar5 * (double)DAT_803de1fc[0x11]) + pfVar2[2]);
    dVar5 = (double)FUN_80293f90();
    dVar7 = (double)FUN_80294964();
    if (dVar4 < (double)DAT_803de1fc[0x10])
    {
        dVar4 = (double)DAT_803de1fc[0x10];
    }
    fVar1 = DAT_803de1fc[4];
    *(float*)uVar9 = (float)(dVar5 * (double)(float)(dVar4 + (double)fVar1) + dVar8);
    *param_3 = -(lbl_803E2658 * ((lbl_803E265C + *(float*)(iVar3 + 0x1c)) - pfVar2[1]) -
        (*(float*)(iVar3 + 0x1c) + DAT_803de1fc[0xc]));
    *param_4 = (float)(dVar7 * (double)(float)(dVar4 + (double)fVar1) + dVar6);
    FUN_80286888();
    return;
}

void FUN_801115e0(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int obj, int state)
{
    u32 spawnActive;
    u16* spawnArgs;
    u32 childObj;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u16 uStack_1a;
    u32 local_18;
    u32 local_14;
    u16 local_10;

    local_18 = DAT_802c2910;
    local_14 = DAT_802c2914;
    local_10 = DAT_802c2918;
    if ((*(char*)(state + 0x407) != *(char*)(state + 0x409)) &&
        (((GameObject*)obj)->anim.alpha != 0))
    {
        if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)obj)->childObjs[0]);
            *(u32*)&((GameObject*)obj)->childObjs[0] = 0;
        }
        spawnActive = FUN_80017ae8();
        if ((spawnActive & 0xff) == 0)
        {
            *(u8*)(state + 0x409) = 0;
        }
        else
        {
            if (0 < *(char*)(state + 0x407))
            {
                spawnArgs = FUN_80017aa4(0x18, (&uStack_1a)[*(char*)(state + 0x407)]);
                childObj = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, spawnArgs,
                                     4, 0xff, 0xffffffff, *(u32**)&((GameObject*)obj)->anim.parent, in_r8, in_r9,
                                     in_r10);
                *(u32*)&((GameObject*)obj)->childObjs[0] = childObj;
                *(u16*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0xb0) = ((GameObject*)obj)->objectFlags &
                    7;
            }
            *(u8*)(state + 0x409) = *(u8*)(state + 0x407);
        }
    }
    return;
}

void CameraModeNpcSpeak_release(void);

#pragma scheduling off
#pragma peephole off
void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void);

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

int dll_19_func1B(int p)
{
    s16 v = *(s16*)((char*)p + 0x46);
    switch (v)
    {
    case 341:
    case 365:
    case 368:
    case 474:
    case 512:
    case 588:
    case 589:
    case 635:
    case 636:
    case 653:
    case 658:
    case 683:
    case 697:
    case 714:
    case 774:
    case 823:
    case 864:
    case 905:
    case 906:
    case 1021:
    case 1197:
    case 1209:
    case 1235:
    case 1276:
    case 1286:
        return 1;
    }
    return 0;
}

void dll_19_func12(int* p1, int* p2, u8 flag)
{
    extern void mm_free(u32); /* #57 */
    Sfx_StopObjectChannel(p1, 127);
    if ((((GroundBaddieState*)p2)->configFlags & flag) == 0)
    {
        s16 v;
        v = *(s16*)((char*)p2 + 1020);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(p1, v, 0, 0, 0);
        }
        v = *(s16*)((char*)p2 + 1018);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(p1, v, 0, 0, 0);
        }
    }
    voxmaps_freeRouteWork((char*)p2 + 900);
    if (*(u32*)((char*)p2 + 988) != 0)
    {
        mm_free(*(u32*)((char*)p2 + 988));
        *(int*)((char*)p2 + 988) = 0;
    }
}

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

void dll_19_func11(void)
{
    (void)(*gCameraInterface)->getOverrideTarget();
}

int dll_19_func0E(int p1, int p2, u8 b)
{
    if (b != 0 && (s8)((BaddieState*)p2)->hitPoints <= 0 && ((GameObject*)p1)->anim.alpha == 0)
    {
        return 0;
    }
    if (*(void**)&((GameObject*)p1)->anim.parent == NULL)
    {
        if (objPosToMapBlockIdx((double)((GameObject*)p1)->anim.localPosX,
                                (double)((GameObject*)p1)->anim.localPosY,
                                (double)((GameObject*)p1)->anim.localPosZ) < 0)
        {
            return 0;
        }
    }
    return 1;
}

f32 dll_19_func1A(int obj)
{
    int p_b8 = *(int*)&((GameObject*)obj)->extra;
    int p_4c = *(int*)&((GameObject*)obj)->anim.placementData;
    u8 denom = ((Dll19Placement*)p_4c)->progressDenominator;
    if (denom != 0)
    {
        s8 numer = ((Dll19State*)p_b8)->progressNumerator;
        if (numer != 0)
        {
            return (f32)numer / denom;
        }
    }
    return lbl_803E1C2C;
}

void dll_19_func0D(int p1, int p2, f32 fval, s8 b)
{
    f32 fz;
    *(u32*)p2 |= 0x8000;
    ((BaddieState*)p2)->cameraYaw = 0;
    if (*(void**)(p1 + 0x54) != NULL)
    {
        ObjHits_SetHitVolumeSlot((void*)p1, 0, 0, -1);
    }
    if (b != -1)
    {
        *(s8*)(p2 + 0x25f) = b;
    }
    ((BaddieState*)p2)->gravity = fval;
    fz = lbl_803E1C2C;
    ((BaddieState*)p2)->moveInputX = fz;
    ((BaddieState*)p2)->moveInputZ = fz;
    *(int*)&((BaddieState*)p2)->unk31C = 0;
    *(int*)&((BaddieState*)p2)->unk318 = 0;
}

void dll_19_func19(u8* cam, u8* ctx)
{
    struct Cfg8
    {
        u32 w0;
        u32 w1;
    };
    s16 buf[5];

    *(struct Cfg8*)&buf[0] = *(struct Cfg8*)lbl_802C2190;
    *(u16*)&buf[4] = *(u16*)(lbl_802C2190 + 8);

    if ((s8)ctx[1031] == (s8)ctx[1033])
    {
        return;
    }
    if (((GameObject*)cam)->anim.alpha == 0)
    {
        return;
    }
    if (*(void**)&((GameObject*)cam)->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(void**)&((GameObject*)cam)->childObjs[0]);
        *(int*)&((GameObject*)cam)->childObjs[0] = 0;
    }
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((s8)ctx[1031] > 0)
        {
            ObjPlacement* setup = Obj_AllocObjectSetup(24, buf[(s8)ctx[1031] - 1]);
            *(int*)&((GameObject*)cam)->childObjs[0] = (int)Obj_SetupObject(
                setup, 4, -1, -1, *(int*)&((GameObject*)cam)->anim.parent);
            *(u16*)(*(int*)&((GameObject*)cam)->childObjs[0] + 0xb0) = ((GameObject*)cam)->objectFlags & 7;
        }
        ctx[1033] = ctx[1031];
    }
    else
    {
        ctx[1033] = 0;
    }
}

#pragma dont_inline on
void dll_19_func0C(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, int p8, s8 p9)
{
    if (p3 != NULL)
    {
        p3[0x24] = 0;
        p3[0x25] = 0;
        p3[0x26] = 4;
        p3[0x27] = 20;
    }
    if (p6 != -1)
    {
        ((BaddieState*)p2)->substate = p6;
        p2[0x27b] = 1;
    }
    if (p7 != -1)
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(p1, p2, p7);
    }
    if (p5 != NULL)
    {
        p5[0] = 2;
    }
    if (p8 != 0)
    {
        ObjAnim_SetCurrentMove(p1, p8, lbl_803E1C2C, 0);
    }
    (*gPathControlInterface)->attachObject((void*)p1, p2 + 4);
    if (p9 != -1)
    {
        p2[0x25f] = p9;
    }
    if (p4 != -1)
    {
        GameBit_Set(p4, 1);
    }
}
#pragma dont_inline reset

int dll_19_func13(int p1, u8* p2, f32 f, int p4)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    int player = Obj_GetPlayerObject();
    int result = 0;

    if ((s8)p2[838] != 0)
    {
        if (((BaddieState*)p2)->targetObj == (void*)player && (s8)((BaddieState*)p2)->hitPoints != 0)
        {
            if (((BaddieState*)p2)->targetDistance > f && p4 != 0)
            {
                result = 1;
            }
            else if (fn_80295A04(player, 1) == 0)
            {
                result = 1;
            }
            else if (Player_GetCurrentHealth(player) <= 0)
            {
                result = 1;
            }
            else
            {
                f32 pos[3];
                f32 out[22];
                pos[0] = ((GameObject*)player)->anim.localPosX;
                pos[1] = lbl_803E1C68 + ((GameObject*)player)->anim.localPosY;
                pos[2] = ((GameObject*)player)->anim.localPosZ;
                if (objBboxFn_800640cc(p1 + 0xc, pos, lbl_803E1C48, 0, out, p1, 4, -1, 0, 0) != 0)
                {
                    result = 1;
                }
            }
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

int dll_19_func10(int p1, u8* p2, int p3, int p4, s16 p5, f32* p6, f32* p7, int* p8)
{
    extern f32 lbl_803E1C68; /* #57 */
    f32 dx, dz, dist;
    f32 zero;

    if (p2[897] != 0)
    {
        *(int*)(p2 + 792) = 0;
        *(int*)(p2 + 796) = 0;
        *(s16*)(p2 + 816) = 0;
        zero = lbl_803E1C2C;
        *(f32*)(p2 + 656) = zero;
        *(f32*)(p2 + 652) = zero;
        *p8 = 1;
        dx = *p6 - ((GameObject*)p1)->anim.localPosX;
        dz = *p7 - ((GameObject*)p1)->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < lbl_803E1C68)
        {
            *p8 = 0;
        }
        else
        {
            dx /= dist;
            dz /= dist;
            *(f32*)(p2 + 656) = lbl_803E1C6C * -dx;
            *(f32*)(p2 + 652) = lbl_803E1C6C * dz;
            ((GameObject*)p1)->anim.localPosX += dist * dx;
            ((GameObject*)p1)->anim.localPosZ += dist * dz;
            (*(void (**)(int, u8*, f32, f32, int, int))(*(int*)gPlayerInterface + 8))(
                p1, p2, timeDelta, timeDelta, p3, p4);
        }
        if (*p8 == 0)
        {
            p2[1029] = 0;
            ((BaddieState*)p2)->controlMode = p5;
            ((BaddieState*)p2)->targetObj = 0;
            p2[607] = 0;
            GameBit_Set(*(s16*)(p2 + 1012), 0);
        }
        return 1;
    }
    return 0;
}

int dll_19_func17(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, s16 p8)
{
    u32 msgData;
    int msgType;
    int extra;

    extra = 0;
    while (ObjMsg_Pop(p1, &msgType, &msgData, &extra) != 0)
    {
        switch (msgType)
        {
        case 4:
            ObjMsg_SendToObject(msgData, 5, p1, 0);
            break;
        case 0xE0000:
            if (msgData == (int)((BaddieState*)p2)->targetObj)
            {
                ((BaddieState*)p2)->substate = p6;
                ((BaddieState*)p2)->targetObj = 0;
                p2[841] = 0;
            }
            break;
        case 11:
            *(s8*)(p2 + 846) = extra;
            break;
        case 1:
        case 0xA0001:
            if (((BaddieState*)p2)->substate != p7)
            {
                dll_19_func0C(p1, p2, p3, p4, p5, p6, p8, 0, 1);
                ((BaddieState*)p2)->substate = p7;
                p2[841] = 0;
                ((BaddieState*)p2)->targetObj = (void*)msgData;
                return 1;
            }
            break;
        case 3:
            if (((BaddieState*)p2)->substate == p7)
            {
                p2[841] = 0;
                ((BaddieState*)p2)->targetObj = 0;
                ((BaddieState*)p2)->substate = p6;
                return 2;
            }
            break;
        }
    }
    return 0;
}

#pragma opt_loop_invariants off
int dll_19_func14(u8* p1, u8* p2, f32 frange, int p4)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    extern int voxmaps_traceLine(int* a, int* b, int c, u8* out, int e); /* #57 */
    f32 bboxOut[20];
    int objs[2];
    f32 diff[3];
    f32 gridIn[3];
    int gridB[2];
    int gridA[2];
    u8 losOut;
    f32* dp = diff;
    int* list;
    int obj;
    int found = 0;
    int negP4;
    int newangle;
    int delta;
    u8 traced;

    objs[0] = Obj_GetPlayerObject();
    objs[1] = 0;
    list = objs;
    negP4 = -p4;

    while ((void*)(obj = *list) != NULL)
    {
        dp[0] = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)p1)->anim.worldPosX;
        dp[1] = ((GameObject*)obj)->anim.worldPosY - ((GameObject*)p1)->anim.worldPosY;
        dp[2] = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)p1)->anim.worldPosZ;
        if (sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1])) < frange)
        {
            if ((s8)((BaddieState*)p2)->hitPoints != 0)
            {
                if (fn_8029610C(obj) > lbl_803E1C64)
                {
                    found = 1;
                }
                newangle = (u16)getAngle(-dp[0], -dp[2]);
                if (*(void**)(p1 + 0x30) != NULL)
                {
                    delta = newangle - (u16)(*(s16*)p1 + *(s16*)(*(int*)&((GameObject*)p1)->anim.parent));
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                else
                {
                    delta = newangle - (u16) * (s16*)p1;
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                if (delta < p4 && delta > negP4)
                {
                    found = 1;
                }
                if (fn_80295A04(obj, 1) == 0)
                {
                    found = 0;
                }
                if (Player_GetCurrentHealth(obj) <= 0)
                {
                    found = 0;
                }
                else
                {
                    gridIn[0] = ((GameObject*)p1)->anim.localPosX;
                    gridIn[1] = lbl_803E1C68 + ((GameObject*)p1)->anim.localPosY;
                    gridIn[2] = ((GameObject*)p1)->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, gridA);
                    gridIn[0] = ((GameObject*)obj)->anim.localPosX;
                    gridIn[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
                    gridIn[2] = ((GameObject*)obj)->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, gridB);
                    traced = voxmaps_traceLine(gridB, gridA, 0, &losOut, 0);
                    if (losOut == 1 || traced != 0)
                    {
                        if (objBboxFn_800640cc((int)p1 + 12, gridIn, lbl_803E1C48, 0, bboxOut,
                                               (int)p1, 4, -1, 0, 0) != 0)
                        {
                            found = 0;
                        }
                    }
                    else
                    {
                        found = 0;
                    }
                }
            }
        }
        list++;
        if (found != 0)
        {
            break;
        }
    }
    return obj;
}
#pragma opt_loop_invariants reset

int dll_19_func16(u8* p1, u8* p2, int p3, int p4, int* p5, u8* p6, s16 p7, u8* p8)
{
    u8* state = *(u8**)(p1 + 184);
    int player = Obj_GetPlayerObject();
    int hit;
    int v28;
    int v24;
    int hitId;
    f32 posX;
    f32 posY;
    f32 posZ;

    if (((Dll19Placement*)state)->oscValue > lbl_803E1C2C)
    {
        ((Dll19Placement*)state)->oscValue = timeDelta * ((Dll19Placement*)state)->oscVelocity + ((Dll19Placement*)state)->oscValue;
        if ((((Dll19Placement*)state)->flags & 0x20) != 0)
        {
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~0x20;
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags | 0x40;
            if (((Dll19Placement*)state)->oscValue > lbl_803E1C40)
            {
                ((Dll19Placement*)state)->oscValue = lbl_803E1C2C;
                ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~0x40;
            }
        }
        else if ((((Dll19Placement*)state)->flags & 0x40) != 0)
        {
            if (((Dll19Placement*)state)->oscValue > lbl_803E1C40)
            {
                int other = *(int*)&((GameObject*)p1)->anim.placementData;
                ((Dll19Placement*)state)->oscValue = lbl_803E1C2C;
                ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~0x40;
                ((BaddieState*)p2)->hitPoints = 0;
                p1[54] = 0;
                ((GameObject*)p1)->unkF4 = 1;
                ((GameObject*)p1)->anim.flags = ((GameObject*)p1)->anim.flags | 0x4000;
                (*gMapEventInterface)->addTime(
                    *(int*)(other + 20),
                    (f32)(s32)(*(s16*)(other + 44) * 60));
            }
        }
        else
        {
            if (((Dll19Placement*)state)->oscValue < lbl_803E1C2C)
            {
                ((Dll19Placement*)state)->oscValue = lbl_803E1C2C;
            }
            else if (((Dll19Placement*)state)->oscValue > lbl_803E1C44)
            {
                ((Dll19Placement*)state)->oscValue = lbl_803E1C44 - (((Dll19Placement*)state)->oscValue - lbl_803E1C44);
                ((Dll19Placement*)state)->oscVelocity = -((Dll19Placement*)state)->oscVelocity;
            }
        }
    }

    if (*(s8*)&((BaddieState*)p2)->hitPoints == 0)
    {
        return 0;
    }
    hit = ObjHits_GetPriorityHitWithPosition(p1, &hitId, &v28, &v24, &posX, &posY, &posZ);
    *(s8*)(state + 1034) = v28;
    if (hit != 0)
    {
        if (p8 != NULL)
        {
            *(f32*)(p8 + 12) = posX + playerMapOffsetX;
            *(f32*)(p8 + 16) = posY;
            *(f32*)(p8 + 20) = posZ + playerMapOffsetZ;
        }
        if (p6 != NULL)
        {
            int hitVal = ((s8*)p6)[hit - 2];
            if (hitVal != -1)
            {
                v24 = hitVal;
            }
        }
        else
        {
            v24 = 0;
        }
        *(s8*)&((BaddieState*)p2)->hitPoints = (s8)(((BaddieState*)p2)->hitPoints - v24);
        if (*(s8*)&((BaddieState*)p2)->hitPoints < 1)
        {
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags | 0x20;
            ((Dll19Placement*)state)->oscValue = lbl_803E1C48;
            ((Dll19Placement*)state)->oscVelocity = lbl_803E1C4C;
            ((BaddieState*)p2)->substate = p7;
            ((BaddieState*)p2)->hitPoints = 0;
        }
        else
        {
            if (v24 != 0)
            {
                if (((BaddieState*)p2)->targetObj == NULL)
                {
                    if (fn_80295A04(player, 1) != 0)
                    {
                        ((BaddieState*)p2)->targetObj = (void*)player;
                        p2[841] = 0;
                    }
                }
                ((Dll19Placement*)state)->oscValue = lbl_803E1C48;
                ((Dll19Placement*)state)->oscVelocity = lbl_803E1C50;
                if (p5 != NULL)
                {
                    if (p5[hit - 2] != -1)
                    {
                        (*(void (**)(u8*, u8*))(*(int*)gPlayerInterface + 20))(p1, p2);
                        ((BaddieState*)p2)->substate = p7;
                    }
                }
                *(s8*)(p2 + 847) = hit;
            }
            Sfx_StopObjectChannel((int*)p1, 16);
            ObjMsg_SendToObject(hitId, 0xe0001, p1, 0);
        }
    }
    return hit;
}

int dll_19_func15(u8* p1, int p2, int p3, int p4)
{
    GameObject* source = (GameObject*)p1;
    u8* state = *(u8**)&((GameObject*)p1)->anim.placementData;
    ObjPlacement* setup;
    u16 ids1[4];
    u16 ids2[4];
    int idx;
    f32 savedX, savedY, savedZ;
    f32 nearDist;
    f32 scale;

    scale = lbl_803E1C2C;
    *(u32*)&ids1[0] = lbl_803E1C18;
    *(u32*)&ids1[2] = lbl_803E1C1C;
    *(u32*)&ids2[0] = lbl_803E1C20;
    *(u32*)&ids2[2] = lbl_803E1C24;
    if (p2 == 0)
    {
        return 0;
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    if ((((Dll19Placement*)state)->stateFlags & 0xf00) != 0)
    {
        idx = ((p2 & 0xf00) >> 8) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids1[idx]);
        scale = lbl_803E1C54;
    }
    if ((((Dll19Placement*)state)->stateFlags & 0xf000) != 0)
    {
        idx = ((p2 & 0xf000) >> 12) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids2[idx]);
        scale = lbl_803E1C54;
    }
    if ((int)(u8)((Dll19Placement*)state)->stateFlags != 0)
    {
        switch (p2)
        {
        case 1:
            setup = Obj_AllocObjectSetup(48, 717);
            scale = lbl_803E1C54;
            break;
        case 2:
            setup = Obj_AllocObjectSetup(48, 9);
            scale = lbl_803E1C54;
            break;
        case 3:
            setup = Obj_AllocObjectSetup(48, 11);
            scale = lbl_803E1C54;
            break;
        case 4:
            setup = Obj_AllocObjectSetup(48, 717);
            scale = lbl_803E1C54;
            break;
        case 5:
            savedX = source->anim.worldPosX;
            savedY = source->anim.worldPosY;
            savedZ = source->anim.worldPosZ;
            {
                ObjPlacement* pl = *(ObjPlacement**)&source->anim.placementData;
                if (pl != NULL)
                {
                    source->anim.worldPosX = pl->posX;
                    source->anim.worldPosY = pl->posY;
                    source->anim.worldPosZ = pl->posZ;
                }
            }
            nearDist = lbl_803E1C58;
            gDll19NearestObj = (GameObject*)ObjGroup_FindNearestObject(4, p1, &nearDist);
            source->anim.worldPosX = savedX;
            source->anim.worldPosY = savedY;
            source->anim.worldPosZ = savedZ;
            if (gDll19NearestObj != NULL)
            {
                f32 xx, yy, zz;
                xx = source->anim.localPosX;
                gDll19NearestObj->anim.worldPosX = xx;
                gDll19NearestObj->anim.localPosX = xx;
                yy = source->anim.localPosY + lbl_803E1C5C;
                gDll19NearestObj->anim.worldPosY = yy;
                gDll19NearestObj->anim.localPosY = yy;
                zz = source->anim.localPosZ;
                gDll19NearestObj->anim.worldPosZ = zz;
                gDll19NearestObj->anim.localPosZ = zz;
            }
            return (int)gDll19NearestObj;
        case 6:
            setup = Obj_AllocObjectSetup(48, 1702);
            *(u8*)((u8*)setup + 27) = 0;
            *(u8*)((u8*)setup + 34) = 0;
            *(u8*)((u8*)setup + 35) = 64;
            scale = lbl_803E1C60;
            break;
        default:
            return 0;
        }
    }
    *(u8*)((u8*)setup + 26) = 20;
    *(s16*)((u8*)setup + 44) = -1;
    *(s16*)((u8*)setup + 28) = -1;
    *(s16*)((u8*)setup + 36) = -1;
    setup->posX = source->anim.localPosX;
    setup->posY = source->anim.localPosY + scale;
    setup->posZ = source->anim.localPosZ;
    if ((u8)p4 != 0)
    {
        *(s16*)((u8*)setup + 46) = 2;
    }
    else
    {
        *(s16*)((u8*)setup + 46) = 1;
    }
    *(u8*)((u8*)setup + 4) = state[4];
    *(u8*)((u8*)setup + 6) = state[6];
    *(u8*)((u8*)setup + 5) = state[5];
    *(u8*)((u8*)setup + 7) = state[7];
    gDll19NearestObj = Obj_SetupObject(setup, 5, ((GameObject*)p1)->anim.mapEventSlot, -1, *(int*)&source->anim.parent);
    return (int)gDll19NearestObj;
}

void dll_19_func18(int p1, u8* p2, u8* p3, int p4, int p5, int p6, f32 fparam, int p7)
{
    u8 flags;
    int b1;
    u8* path;
    int curveLocal;
    u8 byteLocal;

    curveLocal = lbl_803E1C28;
    byteLocal = 1;
    ((GroundBaddieState*)p3)->control = (void*)(p3 + 1040);
    ((GroundBaddieState*)p3)->targetState = 0;

    flags = p7;
    b1 = flags & 1;
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        ObjGroup_AddObject(p1, 3);
        ObjMsg_AllocQueue(p1, 4);
    }
    (*(void (**)(int, u8*, int, int))(*(int*)gPlayerInterface + 4))(p1, p3, p4, p5);
    *(int*)(p3 + 0) = 0;
    p3[841] = 0;
    *(f32*)(p3 + 640) = lbl_803E1C2C;
    *(f32*)(p3 + 644) = lbl_803E1C2C;
    if (p2[50] != 0)
    {
        *(s8*)&p3[852] = (s8)p2[50];
    }
    else
    {
        p3[852] = 6;
    }
    *(s16*)(p3 + 1012) = *(s16*)(p2 + 48);
    *(s16*)(p3 + 1014) = *(s16*)(p2 + 26);
    *(s16*)(p3 + 1016) = *(s16*)(p2 + 28);
    if (*(s16*)(p3 + 1012) != -1)
    {
        GameBit_Set(*(s16*)(p3 + 1012), 0);
    }
    path = p3 + 4;
    if ((flags & 2) != 0)
    {
        (*gPathControlInterface)->init(path, 0, p6 | 0x200000, 1);
    }
    else
    {
        (*gPathControlInterface)->init(path, 0, 0, 0);
    }
    (*gPathControlInterface)->setLocalPointCollision(path, 1, lbl_8031A054, &lbl_803DB9E0, 4);
    if ((flags & 4) != 0)
    {
        (*gPathControlInterface)->setup(path, 1, lbl_8031A048, &lbl_803DD5E0, &byteLocal);
    }
    (*gPathControlInterface)->attachObject((void*)p1, path);
    ((GroundBaddieState*)p3)->configFlags = p2[43];
    *(s16*)(p3 + 1008) = *(s16*)(p2 + 34);
    ((GroundBaddieState*)p3)->aggression = p2[47];
    p3[1031] = p2[39];
    p3[1032] = p2[40];
    ((GameObject*)p1)->objectFlags = ((GameObject*)p1)->objectFlags | ((s8)p3[1032] & 7);
    if ((flags & 8) != 0)
    {
        *(s16*)(p3 + 1018) = *(s16*)(p2 + 32);
        *(s16*)(p3 + 1020) = *(s16*)(p2 + 30);
    }
    else
    {
        *(s16*)(p3 + 1018) = 0;
        *(s16*)(p3 + 1020) = 0;
    }
    *(s16*)(p3 + 1024) = 0;
    ((GroundBaddieState*)p3)->aggroRange = (u16)(p2[41] << 3);
    p3[1029] = 0;
    *(f32*)(p3 + 996) = fparam;
    ((GameObject*)p1)->anim.rotX = (s16)((s8)p2[42] << 8);
    ((GameObject*)p1)->anim.alpha = 255;
    *(u8*)&((GameObject*)p1)->anim.resetHitboxMode = *(u8*)&((GameObject*)p1)->anim.resetHitboxMode & ~0x8;
    *(s16*)(p3 + 1010) = *(s16*)(p2 + 24);
    if (*(s16*)(p3 + 1010) != -1)
    {
        if (((GameObject*)p1)->anim.seqId == 636)
        {
            ((GameObject*)p1)->unkF4 = (GameBit_Get(*(s16*)(p3 + 1010)) == 0);
        }
        else
        {
            ((GameObject*)p1)->unkF4 = GameBit_Get(*(s16*)(p3 + 1010));
        }
    }
    else
    {
        ((GameObject*)p1)->unkF4 = 0;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(*(int*)(p2 + 20)) == 0)
    {
        ((GameObject*)p1)->unkF4 = 1;
    }
    if (((GameObject*)p1)->unkF4 != 0)
    {
        ObjHits_DisableObject(p1);
        ((GameObject*)p1)->anim.flags = ((GameObject*)p1)->anim.flags | 0x4000;
    }
    else
    {
        ((GameObject*)p1)->anim.flags = ((GameObject*)p1)->anim.flags & ~0x4000;
        ObjHits_EnableObject(p1);
    }
    if ((s8)p2[46] == -1)
    {
        ((GameObject*)p1)->unkF8 = 1;
    }
    else
    {
        ((GameObject*)p1)->unkF8 = 0;
    }
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        voxmaps_allocRouteWork(p3 + 900);
        p3[898] = 4;
        p3[899] = 20;
    }
    if ((flags & 0x10) != 0)
    {
        if (*(void**)(p3 + 988) == NULL && (flags & 0x20) == 0)
        {
            *(int*)(p3 + 988) = (int)mmAlloc(264, 26, 0);
        }
        if (*(void**)(p3 + 988) != NULL)
        {
            memset((void*)*(int*)(p3 + 988), 0, 264);
        }
        if ((*gRomCurveInterface)->initCurve((void*)*(int*)(p3 + 988), (void*)p1,
                                             (f32)(u32) * (u16*)(p3 + 1022),
                                             &curveLocal, -1) == 0)
        {
            ((GroundBaddieState*)p3)->flags400 = ((GroundBaddieState*)p3)->flags400 | 8;
        }
    }
    else
    {
        *(int*)(p3 + 988) = 0;
    }
}

int dll_19_func0F(int obj, ObjSeqState* seq, char* st, int p4, int p5, s16 p6)
{
    extern int* gPlayerInterface;
    extern f32 gDll19SeqMinDist;
    extern s8 gDll19SeqStallCount;
    extern const f32 lbl_803E1C2C;
    extern f32 gDll19SeqMinDistInit;
    extern f32 lbl_803E1C74;
    extern const f32 lbl_803E1C6C;
    extern const f32 lbl_803E1C5C;
    extern f32 timeDelta;
    extern f32 sqrtf(f32 x);
    extern u8 framesThisStep;
    f32 dist;
    f32 nx;
    f32 nz;
    char* t;

    *(int*)&((BaddieState*)st)->unk318 = 0;
    *(int*)&((BaddieState*)st)->unk31C = 0;
    ((BaddieState*)st)->cameraYaw = 0;
    {
        f32 rest = lbl_803E1C2C;
        ((BaddieState*)st)->moveInputX = rest;
        ((BaddieState*)st)->moveInputZ = rest;
    }
    if ((s8)seq->movementState != 1)
    {
        seq->posOffsetX = ((GameObject*)obj)->anim.localPosX;
        seq->posOffsetY = ((GameObject*)obj)->anim.localPosY;
        seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ;
        gDll19SeqMinDist = gDll19SeqMinDistInit;
        gDll19SeqStallCount = 0;
    }
    seq->flags = 0;
    seq->movementState = 1;
    {
        f32 ex = seq->posOffsetX - ((GameObject*)obj)->anim.localPosX;
        f32 ez = seq->posOffsetZ - ((GameObject*)obj)->anim.localPosZ;
        dist = sqrtf(ex * ex + ez * ez);
    }
    t = *(char**)&((BaddieState*)st)->targetObj;
    if (t == NULL)
    {
        return 0;
    }
    nx = *(f32*)(t + 0xc) - seq->posOffsetX;
    nz = *(f32*)(t + 0x14) - seq->posOffsetZ;
    {
        f32 total = sqrtf(nx * nx + nz * nz);
        f32 step = timeDelta * (total - dist);
        f32 td;
        step = step * lbl_803E1C74;
        if (step > lbl_803E1C6C)
        {
            step = lbl_803E1C6C;
        }
        else if (step < lbl_803E1C5C)
        {
            step = lbl_803E1C5C;
        }
        if (dist <= gDll19SeqMinDist)
        {
            gDll19SeqStallCount = gDll19SeqStallCount + 1;
        }
        if (dist >= total || gDll19SeqStallCount > 9)
        {
            char* t2 = *(char**)&((BaddieState*)st)->targetObj;
            int delta = ((GameObject*)obj)->anim.rotX - (u16) * (s16*)t2;
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            if (delta > 0x2000)
            {
                delta = 0x2000;
            }
            if (delta < -0x2000)
            {
                delta = -0x2000;
            }
            ((GameObject*)obj)->anim.rotX -= (delta * framesThisStep) >> 3;
            if ((s8)gDll19SeqStallCount > 10)
            {
                delta = 0;
            }
            if (delta < 0x100 && delta > -0x100)
            {
                seq->movementState = 0;
                seq->prevFrame = (s16)(seq->curFrame - 1);
            }
            else
            {
                td = timeDelta;
                (*(void (**)(int, char*, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                    obj, st, td, td, p4, p5);
            }
        }
        else
        {
            nx = nx / total;
            nz = nz / total;
            ((BaddieState*)st)->moveInputX = -nx * step;
            ((BaddieState*)st)->moveInputZ = nz * step;
            ((GameObject*)obj)->anim.localPosX = dist * nx + seq->posOffsetX;
            ((GameObject*)obj)->anim.localPosZ = dist * nz + seq->posOffsetZ;
            td = timeDelta;
            (*(void (**)(int, char*, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                obj, st, td, td, p4, p5);
        }
    }
    gDll19SeqMinDist = dist;
    if ((s8)seq->movementState == 0)
    {
        *(u8*)(st + 0x405) = 0;
        ((BaddieState*)st)->controlMode = p6;
        *(int*)&((BaddieState*)st)->targetObj = 0;
        seq->flags = -1;
        seq->flags = seq->flags & ~0x40;
        ((BaddieState*)st)->physicsActive = 0;
        GameBit_Set(*(s16*)(st + 0x3f4), 0);
    }
    return 1;
}

void dll_19_func04_nop(void)
{
}

void dll_19_func03_nop(void)
{
}

int dll_19_func09_ret_0(void) { return 0x0; }

f32 dll_19_func0B(int* obj) { return *(f32*)((char*)(int*)((GameObject*)obj)->extra + 0x3e4); }

u16 dll_19_func0A(int obj)
{
    void* p = ((GameObject*)obj)->anim.placementData;
    if (p != NULL) return *(u16*)((char*)p + 0x34);
    return 0xd2;
}

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */
void dll_19_func06(s16* yaw, char* st, f32 cap, f32 speed)
{
    if (((BaddieState*)st)->inputMagnitude < lbl_803E1C78)
    {
        f32 rest;
        *(s16*)(st + 0x334) = 0;
        ((BaddieState*)st)->turnRate = 0;
        rest = lbl_803E1C2C;
        ((BaddieState*)st)->inputMagnitude = rest;
        ((BaddieState*)st)->animSpeedA = rest;
    }
    ((BaddieState*)st)->animSpeedB = lbl_803E1C2C;
    *yaw = lbl_803E1C7C * ((f32)((BaddieState*)st)->turnRate * timeDelta / speed) + (f32) * yaw;
    ((BaddieState*)st)->animSpeedC +=
        timeDelta * ((((BaddieState*)st)->inputMagnitude - ((BaddieState*)st)->animSpeedC) / ((BaddieState*)st)->velSmoothTime);
    ((BaddieState*)st)->animSpeedA +=
        timeDelta * ((((BaddieState*)st)->inputMagnitude - ((BaddieState*)st)->animSpeedA) / ((BaddieState*)st)->velSmoothTime);
    if (((BaddieState*)st)->animSpeedC > cap)
    {
        ((BaddieState*)st)->animSpeedC = cap;
    }
    if (((BaddieState*)st)->animSpeedA > cap)
    {
        ((BaddieState*)st)->animSpeedA = cap;
    }
}

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */
void dll_19_func07(int obj, int target, int div, u16* outYaw, u16* outDelta, u16* outDist)
{
    char* st = ((GameObject*)obj)->extra;
    f32 d[3];
    f32* dp = d;
    s16* ovr;
    u16 ang;
    int cur;
    int delta;

    if ((void*)obj == NULL || (void*)target == NULL)
    {
        *outYaw = 0;
        *outDelta = 0;
        *outDist = 0;
    }
    else
    {
        dp[0] = ((GameObject*)target)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = ((GameObject*)target)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = ((GameObject*)target)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ang = getAngle(-dp[0], -dp[2]);
        ovr = *(s16**)&((GameObject*)obj)->anim.parent;
        if (ovr != NULL)
        {
            cur = (s16)(((GameObject*)obj)->anim.rotX + *ovr);
        }
        else
        {
            cur = ((GameObject*)obj)->anim.rotX;
        }
        delta = ang - (u16)(s16)
        cur;
        if (delta > 0x8000)
        {
            delta -= 0xffff;
        }
        if (delta < -0x8000)
        {
            delta += 0xffff;
        }
        *outDelta = delta;
        if ((u16)delta < 0x31c4 || (u16)delta > 0xce3b)
        {
            ((Dll19State*)st)->flags &= ~0x10;
        }
        else
        {
            ((Dll19State*)st)->flags |= 0x10;
        }
        *outYaw = (u16)delta / (0x10000 / (u8)div);
        *outDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
}

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */
u8 dll_19_func08(int obj, char* st, f32 dist)
{
    extern const f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(void* pos, f32* world, f32 rad, int a, void* out, int obj, int b, int c, int d, int e); /* #57 */
    extern u8 voxmaps_traceLine(int* from, int* to, int a, u8* outFlag, int b); /* #57 */
    u16 i;
    u8 mask;
    u8 hitFlag;
    int grid1[2];
    int grid0[2];
    f32 world[3];
    u8 bboxOut[0x54];
    int cur;
    s16* ovr;
    u8 ok;
    f32 a;

    mask = 0;
    world[0] = ((GameObject*)obj)->anim.localPosX;
    world[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
    world[2] = ((GameObject*)obj)->anim.localPosZ;
    voxmaps_worldToGrid(world, grid0);
    ovr = *(s16**)&((GameObject*)obj)->anim.parent;
    if (ovr != NULL)
    {
        cur = (s16)(((GameObject*)obj)->anim.rotX + *ovr);
    }
    else
    {
        cur = ((GameObject*)obj)->anim.rotX;
    }
    for (i = 0; i < 4; i++)
    {
        a = gDll19AnglePi * (f32)((s16)cur + (i << 14)) / gDll19BinaryAngleScale;
        world[0] = ((GameObject*)obj)->anim.localPosX - dist * mathSinf(a);
        world[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
        world[2] = ((GameObject*)obj)->anim.localPosZ - dist * mathCosf(a);
        voxmaps_worldToGrid(world, grid1);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            ok = 1;
        }
        else
        {
            ok = (u8)voxmaps_traceLine(grid1, grid0, 0, &hitFlag, 0);
            if (hitFlag == 1)
            {
                ok = 1;
            }
        }
        if (ok != 0)
        {
            if (objBboxFn_800640cc((char*)(obj + 0xc), world, lbl_803E1C48, 0, bboxOut, obj,
                                   *(u8*)(st + 0x261), -1, 0, 0) != 0)
            {
                ok = 0;
            }
        }
        mask |= ok << i;
    }
    return mask;
}

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */
f32 dll_19_func05(int obj, f32 px, f32 pz, f32 range, char* st)
{
    f32 dist;
    f32 fz;
    f32 fx;
    f32 c;
    f32 s;
    f32 dx;
    f32 dz;

    dx = ((BaddieState*)st)->posY - px;
    dz = *(f32*)(st + 0x20) - pz;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist < range)
    {
        f32 base;
        f32 d1;
        f32 d2;
        c = mathSinf(gDll19AnglePi * (f32)((GameObject*)obj)->anim.rotX / gDll19BinaryAngleScale);
        s = mathCosf(gDll19AnglePi * (f32)((GameObject*)obj)->anim.rotX / gDll19BinaryAngleScale);
        base = -(c * (px - c) + s * (pz - s));
        d1 = base + (c * ((BaddieState*)st)->posY + s * *(f32*)(st + 0x20));
        d2 = base + (c * *(f32*)(st + 0x8c) + s * *(f32*)(st + 0x94));
        if (d1 > lbl_803E1C2C && d2 <= lbl_803E1C48)
        {
            ((BaddieState*)st)->posY = ((BaddieState*)st)->posY - c * d1;
            *(f32*)(st + 0x20) = *(f32*)(st + 0x20) - s * d1;
            Obj_TransformWorldPointToLocal(((BaddieState*)st)->posY, ((BaddieState*)st)->posZ,
                                           *(f32*)(st + 0x20), (f32*)(st + 0xc),
                                           (f32*)(st + 0x10), (f32*)(st + 0x14),
                                           *(u32*)(st + 0x30));
        }
        else if (d2 > lbl_803E1C48)
        {
            dist = lbl_803E1C40 * range;
        }
    }
    if (dist < range)
    {
        fx = ((BaddieState*)st)->posY;
        fz = *(f32*)(st + 0x20);
    }
    else
    {
        fx = px;
        fz = pz;
    }
    c = mathSinf(gDll19AnglePi * (f32)(((GameObject*)obj)->anim.rotX + 0x4000) / gDll19BinaryAngleScale);
    s = mathCosf(gDll19AnglePi * (f32)(((GameObject*)obj)->anim.rotX + 0x4000) / gDll19BinaryAngleScale);
    return -(-(((GameObject*)obj)->anim.localPosX * c + ((GameObject*)obj)->anim.localPosZ * s) + (c * fx + s * fz));
}

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
