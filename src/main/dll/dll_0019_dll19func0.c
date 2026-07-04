/* DLL 0x0019 — dll19 / camDebug group. TU: 0x8010DB7C–0x8010DD58. */
#include "main/game_object.h"
#include "main/mm.h"
#include "main/objseq.h"

/* object group this object joins */
#define DLL19_OBJGROUP 3
#define DLL19_ADVANCE_MSG 0xe0001 /* notify the struck object to advance its hit reaction */
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

#include "main/camera_interface.h"
#include "main/dll/CAM/camcloudrunner_state.h"
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

/* bits in the u16 flags word at +0x400 (shared Dll19State/Dll19Placement view) */
#define DLL19_FLAG_YAW_ALIGNED 0x10 /* yaw delta within facing cone */
#define DLL19_FLAG_OSC_RISING 0x20  /* oscillation phase 1 (initial rise) */
#define DLL19_FLAG_OSC_ACTIVE 0x40  /* oscillation phase 2 (active/return) */

extern void ObjHits_DisableObject(u32 objPtr);
extern void ObjHits_EnableObject(u32 objPtr);
extern int ObjHits_GetPriorityHitWithPosition();
extern u32 ObjGroup_FindNearestObject();
extern void ObjGroup_AddObject(u32 obj, int group);
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern u32 ObjMsg_AllocQueue();
extern void** gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

#pragma scheduling on
#pragma peephole on

extern f32 timeDelta;
extern void Sfx_StopObjectChannel(int* p1, int channel);
extern void voxmaps_freeRouteWork(void* p);
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
extern u32 lbl_803E1C20;
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

#pragma scheduling off
#pragma peephole off
void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

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

void dll_19_func12(int* obj, int* state, u8 flag)
{
    extern void mm_free(u32); /* #57 */
    Sfx_StopObjectChannel(obj, 127);
    if ((((GroundBaddieState*)state)->configFlags & flag) == 0)
    {
        s16 v;
        v = *(s16*)((char*)state + 1020);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(obj, v, 0, 0, 0);
        }
        v = *(s16*)((char*)state + 1018);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(obj, v, 0, 0, 0);
        }
    }
    voxmaps_freeRouteWork((char*)state + 900);
    if (*(u32*)((char*)state + 988) != 0)
    {
        mm_free(*(u32*)((char*)state + 988));
        *(int*)((char*)state + 988) = 0;
    }
}

void dll_19_func11(void)
{
    (void)(*gCameraInterface)->getOverrideTarget();
}

int dll_19_func0E(int obj, int state, u8 checkDead)
{
    if (checkDead != 0 && (s8)((BaddieState*)state)->hitPoints <= 0 && ((GameObject*)obj)->anim.alpha == 0)
    {
        return 0;
    }
    if (*(void**)&((GameObject*)obj)->anim.parent == NULL)
    {
        if (objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                (double)((GameObject*)obj)->anim.localPosY,
                                (double)((GameObject*)obj)->anim.localPosZ) < 0)
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

void dll_19_func0D(int obj, int state, f32 gravity, s8 field25f)
{
    f32 fz;
    *(u32*)state |= 0x8000;
    ((BaddieState*)state)->cameraYaw = 0;
    if (*(void**)(obj + 0x54) != NULL)
    {
        ObjHits_SetHitVolumeSlot((void*)obj, 0, 0, -1);
    }
    if (field25f != -1)
    {
        *(s8*)(state + 0x25f) = field25f;
    }
    ((BaddieState*)state)->gravity = gravity;
    fz = lbl_803E1C2C;
    ((BaddieState*)state)->moveInputX = fz;
    ((BaddieState*)state)->moveInputZ = fz;
    *(int*)&((BaddieState*)state)->unk31C = 0;
    *(int*)&((BaddieState*)state)->unk318 = 0;
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
void dll_19_func0C(int obj, u8* state, u8* hitbox, s16 gameBit, u8* flagOut, s16 substate, s16 moveMode, int animMove, s8 field25f)
{
    if (hitbox != NULL)
    {
        hitbox[0x24] = 0;
        hitbox[0x25] = 0;
        hitbox[0x26] = 4;
        hitbox[0x27] = 20;
    }
    if (substate != -1)
    {
        ((BaddieState*)state)->substate = substate;
        state[0x27b] = 1;
    }
    if (moveMode != -1)
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, state, moveMode);
    }
    if (flagOut != NULL)
    {
        flagOut[0] = 2;
    }
    if (animMove != 0)
    {
        ObjAnim_SetCurrentMove(obj, animMove, lbl_803E1C2C, 0);
    }
    (*gPathControlInterface)->attachObject((void*)obj, state + 4);
    if (field25f != -1)
    {
        state[0x25f] = field25f;
    }
    if (gameBit != -1)
    {
        GameBit_Set(gameBit, 1);
    }
}
#pragma dont_inline reset

int dll_19_func13(int obj, u8* state, f32 distThreshold, int requireFar)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    int player = Obj_GetPlayerObject();
    int result = 0;

    if ((s8)state[838] != 0)
    {
        if (((BaddieState*)state)->targetObj == (void*)player && (s8)((BaddieState*)state)->hitPoints != 0)
        {
            if (((BaddieState*)state)->targetDistance > distThreshold && requireFar != 0)
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
                if (objBboxFn_800640cc(obj + 0xc, pos, lbl_803E1C48, 0, out, obj, 4, -1, 0, 0) != 0)
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

int dll_19_func10(int obj, u8* state, int moveArg0, int moveArg1, s16 controlMode, f32* destX, f32* destZ, int* reachedOut)
{
    extern f32 lbl_803E1C68; /* #57 */
    f32 dx, dz, dist;
    f32 zero;

    if (state[897] != 0)
    {
        *(int*)&((BaddieState*)state)->unk318 = 0;
        *(int*)&((BaddieState*)state)->unk31C = 0;
        ((BaddieState*)state)->cameraYaw = 0;
        zero = lbl_803E1C2C;
        ((BaddieState*)state)->moveInputX = zero;
        ((BaddieState*)state)->moveInputZ = zero;
        *reachedOut = 1;
        dx = *destX - ((GameObject*)obj)->anim.localPosX;
        dz = *destZ - ((GameObject*)obj)->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < lbl_803E1C68)
        {
            *reachedOut = 0;
        }
        else
        {
            dx /= dist;
            dz /= dist;
            ((BaddieState*)state)->moveInputX = lbl_803E1C6C * -dx;
            ((BaddieState*)state)->moveInputZ = lbl_803E1C6C * dz;
            ((GameObject*)obj)->anim.localPosX += dist * dx;
            ((GameObject*)obj)->anim.localPosZ += dist * dz;
            (*(void (**)(int, u8*, f32, f32, int, int))(*(int*)gPlayerInterface + 8))(
                obj, state, timeDelta, timeDelta, moveArg0, moveArg1);
        }
        if (*reachedOut == 0)
        {
            state[1029] = 0;
            ((BaddieState*)state)->controlMode = controlMode;
            ((BaddieState*)state)->targetObj = 0;
            state[607] = 0;
            GameBit_Set(((GroundBaddieState*)state)->gameBitB, 0);
        }
        return 1;
    }
    return 0;
}

int dll_19_func17(int obj, u8* state, u8* hitbox, s16 gameBit, u8* flagOut, s16 substateIdle, s16 substateActive, s16 moveMode)
{
    u32 msgData;
    int msgType;
    int extra;

    extra = 0;
    while (ObjMsg_Pop(obj, &msgType, &msgData, &extra) != 0)
    {
        switch (msgType)
        {
        case 4:
            ObjMsg_SendToObject(msgData, 5, obj, 0);
            break;
        case 0xE0000:
            if (msgData == (int)((BaddieState*)state)->targetObj)
            {
                ((BaddieState*)state)->substate = substateIdle;
                ((BaddieState*)state)->targetObj = 0;
                state[841] = 0;
            }
            break;
        case 11:
            *(s8*)(state + 846) = extra;
            break;
        case 1:
        case 0xA0001:
            if (((BaddieState*)state)->substate != substateActive)
            {
                dll_19_func0C(obj, state, hitbox, gameBit, flagOut, substateIdle, moveMode, 0, 1);
                ((BaddieState*)state)->substate = substateActive;
                state[841] = 0;
                ((BaddieState*)state)->targetObj = (void*)msgData;
                return 1;
            }
            break;
        case 3:
            if (((BaddieState*)state)->substate == substateActive)
            {
                state[841] = 0;
                ((BaddieState*)state)->targetObj = 0;
                ((BaddieState*)state)->substate = substateIdle;
                return 2;
            }
            break;
        }
    }
    return 0;
}

#pragma opt_loop_invariants off
int dll_19_func14(u8* self, u8* state, f32 frange, int halfAngle)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    extern int voxmaps_traceLine(int* a, int* b, int c, u8* out, int e); /* #57 */
    f32 bboxOut[20];
    int objs[3];
    f32 diff[3];
    f32 gridIn[3];
    int gridB[2];
    int gridA[2];
    u8 losOut;
    f32* dp;
    int* list;
    int negHalfAngle;
    int obj;
    int found = 0;
    int delta;
    u8 traced;

    objs[0] = Obj_GetPlayerObject();
    objs[1] = 0;
    dp = diff;
    list = objs;
    negHalfAngle = -halfAngle;

    while (found == 0 && (void*)(obj = *list) != NULL)
    {
        dp[0] = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)self)->anim.worldPosX;
        dp[1] = ((GameObject*)obj)->anim.worldPosY - ((GameObject*)self)->anim.worldPosY;
        dp[2] = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)self)->anim.worldPosZ;
        if (sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1])) < frange)
        {
            if ((s8)((BaddieState*)state)->hitPoints != 0)
            {
                if (fn_8029610C(obj) > lbl_803E1C64)
                {
                    found = 1;
                }
                delta = getAngle(-dp[0], -dp[2]) & 0xffff;
                if (*(void**)(self + 0x30) != NULL)
                {
                    delta -= (*(s16*)self + *(s16*)(*(int*)&((GameObject*)self)->anim.parent)) & 0xffff;
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
                    delta -= *(s16*)self & 0xffff;
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                if (delta < halfAngle && delta > negHalfAngle)
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
                    gridIn[0] = ((GameObject*)self)->anim.localPosX;
                    gridIn[1] = lbl_803E1C68 + ((GameObject*)self)->anim.localPosY;
                    gridIn[2] = ((GameObject*)self)->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, gridA);
                    gridIn[0] = ((GameObject*)obj)->anim.localPosX;
                    gridIn[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
                    gridIn[2] = ((GameObject*)obj)->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, gridB);
                    traced = voxmaps_traceLine(gridB, gridA, 0, &losOut, 0);
                    if (losOut == 1 || traced != 0)
                    {
                        if (objBboxFn_800640cc((int)self + 12, gridIn, lbl_803E1C48, 0, bboxOut,
                                               (int)self, 4, -1, 0, 0) != 0)
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
    }
    return obj;
}
#pragma opt_loop_invariants reset

int dll_19_func16(u8* obj, u8* baddieState, int unusedA, int unusedB, int* tableA, u8* tableB, s16 substate, u8* hitPosOut)
{
    u8* state = *(u8**)(obj + 184);
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
        if ((((Dll19Placement*)state)->flags & DLL19_FLAG_OSC_RISING) != 0)
        {
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~DLL19_FLAG_OSC_RISING;
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags | DLL19_FLAG_OSC_ACTIVE;
            if (((Dll19Placement*)state)->oscValue > lbl_803E1C40)
            {
                ((Dll19Placement*)state)->oscValue = lbl_803E1C2C;
                ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~DLL19_FLAG_OSC_ACTIVE;
            }
        }
        else if ((((Dll19Placement*)state)->flags & DLL19_FLAG_OSC_ACTIVE) != 0)
        {
            if (((Dll19Placement*)state)->oscValue > lbl_803E1C40)
            {
                int other = *(int*)&((GameObject*)obj)->anim.placementData;
                ((Dll19Placement*)state)->oscValue = lbl_803E1C2C;
                ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags & ~DLL19_FLAG_OSC_ACTIVE;
                ((BaddieState*)baddieState)->hitPoints = 0;
                obj[54] = 0;
                ((GameObject*)obj)->unkF4 = 1;
                ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
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

    if (*(s8*)&((BaddieState*)baddieState)->hitPoints == 0)
    {
        return 0;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &hitId, &v28, &v24, &posX, &posY, &posZ);
    *(s8*)(state + 1034) = v28;
    if (hit != 0)
    {
        if (hitPosOut != NULL)
        {
            *(f32*)(hitPosOut + 12) = posX + playerMapOffsetX;
            *(f32*)(hitPosOut + 16) = posY;
            *(f32*)(hitPosOut + 20) = posZ + playerMapOffsetZ;
        }
        if (tableB != NULL)
        {
            int hitVal = (s8)tableB[hit - 2];
            if (hitVal != -1)
            {
                v24 = hitVal;
            }
        }
        else
        {
            v24 = 0;
        }
        *(s8*)&((BaddieState*)baddieState)->hitPoints = (s8)(((BaddieState*)baddieState)->hitPoints - v24);
        if (*(s8*)&((BaddieState*)baddieState)->hitPoints < 1)
        {
            ((Dll19Placement*)state)->flags = ((Dll19Placement*)state)->flags | DLL19_FLAG_OSC_RISING;
            ((Dll19Placement*)state)->oscValue = lbl_803E1C48;
            ((Dll19Placement*)state)->oscVelocity = lbl_803E1C4C;
            ((BaddieState*)baddieState)->substate = substate;
            ((BaddieState*)baddieState)->hitPoints = 0;
        }
        else
        {
            if (v24 != 0)
            {
                if (((BaddieState*)baddieState)->targetObj == NULL)
                {
                    if (fn_80295A04(player, 1) != 0)
                    {
                        ((BaddieState*)baddieState)->targetObj = (void*)player;
                        baddieState[841] = 0;
                    }
                }
                ((Dll19Placement*)state)->oscValue = lbl_803E1C48;
                ((Dll19Placement*)state)->oscVelocity = lbl_803E1C50;
                if (tableA != NULL)
                {
                    if (tableA[hit - 2] != -1)
                    {
                        (*(void (**)(u8*, u8*, int))(*(int*)gPlayerInterface + 20))(obj, baddieState, tableA[hit - 2]);
                        ((BaddieState*)baddieState)->substate = substate;
                    }
                }
                *(s8*)(baddieState + 847) = hit;
            }
        }
        Sfx_StopObjectChannel((int*)obj, 16);
        ObjMsg_SendToObject(hitId, DLL19_ADVANCE_MSG, obj, 0);
    }
    return hit;
}

typedef struct { u32 w0, w1; } IdPair;

int dll_19_func15(u8* obj, int spawnType, int unused, int alt)
{
    GameObject* source = (GameObject*)obj;
    u8* state = *(u8**)&((GameObject*)obj)->anim.placementData;
    ObjPlacement* setup;
    u16 ids1[4];
    u16 ids2[4];
    int idx;
    f32 savedX, savedY, savedZ;
    f32 nearDist;
    f32 scale;

    scale = lbl_803E1C2C;
    *(IdPair*)ids1 = *(IdPair*)&lbl_803E1C18;
    *(IdPair*)ids2 = *(IdPair*)&lbl_803E1C20;
    if (spawnType == 0)
    {
        return 0;
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    if ((((Dll19Placement*)state)->stateFlags & 0xf00) != 0)
    {
        idx = ((spawnType & 0xf00) >> 8) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids1[idx]);
        scale = lbl_803E1C54;
    }
    if ((((Dll19Placement*)state)->stateFlags & 0xf000) != 0)
    {
        idx = ((spawnType & 0xf000) >> 12) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids2[idx]);
        scale = lbl_803E1C54;
    }
    if ((int)(u8)((Dll19Placement*)state)->stateFlags != 0)
    {
        switch (spawnType)
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
            gDll19NearestObj = (GameObject*)ObjGroup_FindNearestObject(4, obj, &nearDist);
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
    if ((u8)alt != 0)
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
    gDll19NearestObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&source->anim.parent);
    return (int)gDll19NearestObj;
}

void dll_19_func18(int obj, u8* config, u8* state, int moveArg0, int moveArg1, int pathFlags, f32 fparam, int initFlags)
{
    u8 flags;
    int b1;
    u8* path;
    int curveLocal;
    u8 byteLocal;

    curveLocal = lbl_803E1C28;
    byteLocal = 1;
    ((GroundBaddieState*)state)->control = (void*)(state + 1040);
    ((GroundBaddieState*)state)->targetState = 0;

    flags = initFlags;
    b1 = flags & 1;
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        ObjGroup_AddObject(obj, DLL19_OBJGROUP);
        ObjMsg_AllocQueue(obj, 4);
    }
    (*(void (**)(int, u8*, int, int))(*(int*)gPlayerInterface + 4))(obj, state, moveArg0, moveArg1);
    *(int*)(state + 0) = 0;
    state[841] = 0;
    ((BaddieState*)state)->animSpeedA = lbl_803E1C2C;
    ((BaddieState*)state)->animSpeedB = lbl_803E1C2C;
    if (config[50] != 0)
    {
        *(s8*)&state[852] = (s8)config[50];
    }
    else
    {
        state[852] = 6;
    }
    ((GroundBaddieState*)state)->gameBitB = *(s16*)(config + 48);
    ((GroundBaddieState*)state)->gameBitC = *(s16*)(config + 26);
    *(s16*)(state + 1016) = *(s16*)(config + 28);
    if (((GroundBaddieState*)state)->gameBitB != -1)
    {
        GameBit_Set(((GroundBaddieState*)state)->gameBitB, 0);
    }
    path = state + 4;
    if ((flags & 2) != 0)
    {
        (*gPathControlInterface)->init(path, 0, pathFlags | 0x200000, 1);
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
    (*gPathControlInterface)->attachObject((void*)obj, path);
    ((GroundBaddieState*)state)->configFlags = config[43];
    ((GroundBaddieState*)state)->triggerId = *(s16*)(config + 34);
    ((GroundBaddieState*)state)->aggression = config[47];
    state[1031] = config[39];
    state[1032] = config[40];
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | ((s8)state[1032] & 7);
    if ((flags & 8) != 0)
    {
        ((GroundBaddieState*)state)->unk3FA = *(s16*)(config + 32);
        ((GroundBaddieState*)state)->unk3FC = *(s16*)(config + 30);
    }
    else
    {
        ((GroundBaddieState*)state)->unk3FA = 0;
        ((GroundBaddieState*)state)->unk3FC = 0;
    }
    ((GroundBaddieState*)state)->flags400 = 0;
    ((GroundBaddieState*)state)->aggroRange = (u16)(config[41] << 3);
    state[1029] = 0;
    *(f32*)(state + 996) = fparam;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)config[42] << 8);
    ((GameObject*)obj)->anim.alpha = 255;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
    ((GroundBaddieState*)state)->gameBitA = *(s16*)(config + 24);
    if (((GroundBaddieState*)state)->gameBitA != -1)
    {
        if (((GameObject*)obj)->anim.seqId == 636)
        {
            ((GameObject*)obj)->unkF4 = (GameBit_Get(((GroundBaddieState*)state)->gameBitA) == 0);
        }
        else
        {
            ((GameObject*)obj)->unkF4 = GameBit_Get(((GroundBaddieState*)state)->gameBitA);
        }
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 0;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(*(int*)(config + 20)) == 0)
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        return;
    }
    ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    if ((s8)config[46] == -1)
    {
        ((GameObject*)obj)->unkF8 = 1;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = 0;
    }
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        voxmaps_allocRouteWork(state + 900);
        state[898] = 4;
        state[899] = 20;
    }
    if ((flags & 0x10) != 0)
    {
        if (((GroundBaddieState*)state)->path == NULL && (flags & 0x20) == 0)
        {
            *(int*)&((GroundBaddieState*)state)->path = (int)mmAlloc(264, 26, 0);
        }
        if (((GroundBaddieState*)state)->path != NULL)
        {
            memset(((GroundBaddieState*)state)->path, 0, 264);
        }
        if ((*gRomCurveInterface)->initCurve(((GroundBaddieState*)state)->path, (void*)obj,
                                             (f32)(u32) * (u16*)(state + 1022),
                                             &curveLocal, -1) == 0)
        {
            ((GroundBaddieState*)state)->flags400 = ((GroundBaddieState*)state)->flags400 | BADDIE_FLAG400_PATH_ACTIVE;
        }
    }
    else
    {
        *(int*)&((GroundBaddieState*)state)->path = 0;
    }
}

int dll_19_func0F(int obj, ObjSeqState* seq, char* st, int moveArg0, int moveArg1, s16 controlMode)
{
    extern f32 gDll19SeqMinDist;
    extern s8 gDll19SeqStallCount;
    extern const f32 lbl_803E1C2C;
    extern f32 gDll19SeqMinDistInit;
    extern f32 lbl_803E1C74;
    extern const f32 lbl_803E1C6C;
    extern const f32 lbl_803E1C5C;
    extern f32 timeDelta;
    extern f32 sqrtf(f32 x);
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
                    obj, st, td, td, moveArg0, moveArg1);
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
                obj, st, td, td, moveArg0, moveArg1);
        }
    }
    gDll19SeqMinDist = dist;
    if ((s8)seq->movementState == 0)
    {
        ((GroundBaddieState*)st)->subMode = 0;
        ((BaddieState*)st)->controlMode = controlMode;
        *(int*)&((BaddieState*)st)->targetObj = 0;
        seq->flags = -1;
        seq->flags = seq->flags & ~0x40;
        ((BaddieState*)st)->physicsActive = 0;
        GameBit_Set(((GroundBaddieState*)st)->gameBitB, 0);
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
            ((Dll19State*)st)->flags &= ~DLL19_FLAG_YAW_ALIGNED;
        }
        else
        {
            ((Dll19State*)st)->flags |= DLL19_FLAG_YAW_ALIGNED;
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
