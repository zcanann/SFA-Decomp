#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/dll/landedArwing.h"
#include "main/dll/dll_00D3_staffAction.h"
#include "main/objhits.h"

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017788();
extern int FUN_80017a98();
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int atan2_8002178c(f32 dx, f32 dz);
extern undefined4 FUN_800305f8();
extern undefined8 ObjGroup_RemoveObject();
extern void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
extern void mtx44_mult(f32 * lhs, f32 * rhs, f32 * out);
extern void fn_8003B950(void* mtx);
extern int hitDetectFn_80067958(int obj, f32* startPoints, f32* endPoints, int pointCount,
                                void* hits, int hitCount);
extern void hitDetectFn_800691c0(int obj, void* bounds, uint mask, int flags);
extern int FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void hitDetect_calcSweptSphereBounds(uint* boundsOut, float* startPoints, float* endPoints, float* radii,
                                            int pointCount);
extern void trackDolphin_buildSweptBounds(uint* boundsOut, float* startPoints, float* endPoints,
                                          float* radii, int pointCount);
extern f32 fsin16Precise(int angle);
extern f32 fcos16Precise(int angle);
extern f32 sqrtf(f32 x);
extern double FUN_80293900();
extern undefined4 FUN_80293bc4();
extern undefined4 FUN_80293f80();

extern undefined4 DAT_803dc070;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DC074;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E3004;
extern f32 lbl_803E3020;
extern f32 lbl_803E3024;
extern f32 lbl_803E3028;
extern f32 lbl_803E302C;
extern f32 lbl_803E3030;
extern f32 lbl_803E3C70;
extern f32 lbl_803E3C74;
extern f32 lbl_803E3C8C;
extern f32 lbl_803E3C9C;
extern f32 lbl_803E3CA0;
extern f32 lbl_803E3CA4;
extern f32 lbl_803E3CA8;
extern f32 lbl_803E3CB8;
extern f32 lbl_803E3CBC;
extern f32 lbl_803E3CC0;
extern f32 lbl_803E3CC4;
extern f32 lbl_803E3CC8;

undefined4
#pragma scheduling on
#pragma peephole on
FUN_801659b8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* obj, uint* params,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int target;
    uint mode;
    int state;
    double trig;
    double targetX;
    double targetZ;
    double targetY;
    double speed;

    state = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    target = FUN_80017a98();
    *(undefined*)((int)params + 0x34d) = 1;
    if (*(char*)((int)params + 0x27a) != '\0')
    {
        *(float*)(state + 0x60) = lbl_803E3C9C;
        ObjHits_EnableObject((u32)obj);
        trig = (double)FUN_80293bc4();
        ((GameObject*)obj)->anim.velocityX = (float)(-(double)*(float*)(state + 0x60) * trig);
        ((GameObject*)obj)->anim.velocityY = lbl_803E3C74;
        trig = (double)FUN_80293f80();
        ((GameObject*)obj)->anim.velocityZ = (float)(-(double)*(float*)(state + 0x60) * trig);
        *params = *params | 0x2004000;
        FUN_800305f8((double)lbl_803E3C74, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(float*)(state + 0x44) = lbl_803E3CA0;
    }
    ObjHits_SetHitVolumeSlot((u32)obj, 9, 1, -1);
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6c) = 9;
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6d) = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    (*gPathControlInterface)->advance(obj, params + 1, lbl_803DC074);
    if (*(char*)(state + 0x90) == '\x06')
    {
        if ((*(byte*)(state + 0x92) & 1) == 0)
        {
            mode = 0;
        }
        else
        {
            mode = 2;
            if ((ushort)DAT_803dc070 < *(ushort*)(state + 0x8e))
            {
                *(ushort*)(state + 0x8e) = *(ushort*)(state + 0x8e) - (ushort)DAT_803dc070;
            }
            else
            {
                *(byte*)(state + 0x92) = *(byte*)(state + 0x92) & 0xfe;
            }
        }
    }
    else if ((((target == 0) || (*(float*)(target + 0x18) < *(float*)(state + 0x48))) ||
            (*(float*)(state + 0x4c) < *(float*)(target + 0x18))) ||
        (((*(float*)(target + 0x1c) < *(float*)(state + 0x5c) ||
                (*(float*)(state + 0x58) < *(float*)(target + 0x1c))) ||
            ((*(float*)(target + 0x20) < *(float*)(state + 0x54) ||
                (*(float*)(state + 0x50) < *(float*)(target + 0x20)))))))
    {
        mode = 1;
    }
    else
    {
        mode = 0;
    }
    if (mode == 1)
    {
        if ((ushort)DAT_803dc070 < *(ushort*)(state + 0x8c))
        {
            *(ushort*)(state + 0x8c) = *(ushort*)(state + 0x8c) - (ushort)DAT_803dc070;
        }
        else
        {
            mode = randomGetRange((int)*(float*)(state + 0x48), (int)*(float*)(state + 0x4c));
            *(float*)(state + 100) =
                (f32)(s32)(mode);
            mode = randomGetRange((int)*(float*)(state + 0x5c), (int)*(float*)(state + 0x58));
            *(float*)(state + 0x68) =
                (f32)(s32)(mode);
            mode = randomGetRange((int)*(float*)(state + 0x54), (int)*(float*)(state + 0x50));
            *(float*)(state + 0x6c) =
                (f32)(s32)(mode);
            mode = randomGetRange(300, 600);
            *(short*)(state + 0x8c) = (short)mode;
        }
        targetX = (double)*(float*)(state + 100);
        targetZ = (double)*(float*)(state + 0x68);
        targetY = (double)*(float*)(state + 0x6c);
        speed = (double)lbl_803E3CA8;
    }
    else if (mode == 0)
    {
        targetX = (double)*(float*)(target + 0xc);
        targetZ = (double)(*(float*)(target + 0x10) - lbl_803E3C70);
        targetY = (double)*(float*)(target + 0x14);
        speed = (double)lbl_803E3CA4;
        mode = GameBit_Get(0x698);
        if (mode != 0)
        {
            speed = -(double)lbl_803E3CA4;
        }
    }
    else if (mode < 3)
    {
        targetX = (double)*(float*)(state + 0x70);
        targetZ = (double)*(float*)(state + 0x74);
        targetY = (double)*(float*)(state + 0x78);
        speed = (double)lbl_803E3CA4;
    }
    FUN_80166e9c(targetX, targetZ, targetY, speed, (int)obj);
    if (*(char*)(state + 0x90) == '\x06')
    {
        if ((*(byte*)(state + 0x92) >> 2 & 1) == 0)
        {
            FUN_8016693c((int)obj, state);
        }
        else
        {
            FUN_801660c0((int)obj, state);
        }
    }
    else
    {
        FUN_801661ec(obj, state);
    }
    return 0;
}

undefined4
FUN_80165e74(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* obj, uint* params,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int state;
    double trig;

    state = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(undefined*)((int)params + 0x34d) = 1;
    if (*(char*)((int)params + 0x27a) != '\0')
    {
        *(float*)(state + 0x60) = lbl_803E3C9C;
        ObjHits_EnableObject((u32)obj);
        trig = (double)FUN_80293bc4();
        ((GameObject*)obj)->anim.velocityX = (float)(-(double)*(float*)(state + 0x60) * trig);
        ((GameObject*)obj)->anim.velocityY = lbl_803E3C74;
        trig = (double)FUN_80293f80();
        ((GameObject*)obj)->anim.velocityZ = (float)(-(double)*(float*)(state + 0x60) * trig);
        *params = *params | 0x2004000;
        FUN_800305f8((double)lbl_803E3C74, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(float*)(state + 0x44) = lbl_803E3C74;
    }
    ObjHits_SetHitVolumeSlot((u32)obj, 9, 1, -1);
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6c) = 9;
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6d) = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    (*gPathControlInterface)->advance(obj, params + 1, lbl_803DC074);
    if (*(char*)((int)params + 0x27a) != '\0')
    {
        if (*(char*)(state + 0x90) == '\x06')
        {
            if ((*(byte*)(state + 0x92) >> 2 & 1) == 0)
            {
                FUN_8016693c((int)obj, state);
            }
            else
            {
                FUN_801660c0((int)obj, state);
            }
        }
        else
        {
            FUN_801661ec(obj, state);
        }
    }
    return 0;
}

void FUN_801660c0(int obj, int state)
{
    float damping;
    int hitFound;
    float local_b8;
    float local_b4;
    float local_b0;
    float local_ac;
    float local_a8;
    float local_a4;
    float local_a0;
    uint auStack_9c[6];
    float afStack_84[16];
    float local_44;
    undefined local_30;

    local_b8 = lbl_803E3CB8;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E3C8C;
    damping = lbl_803E3CBC;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * lbl_803E3CBC;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * damping;
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * damping;
    local_a8 = ((GameObject*)obj)->anim.localPosX;
    local_a4 = ((GameObject*)obj)->anim.localPosY;
    local_a0 = ((GameObject*)obj)->anim.localPosZ;
    local_b4 = local_a8 + ((GameObject*)obj)->anim.velocityX;
    local_b0 = local_a4 + ((GameObject*)obj)->anim.velocityY;
    local_ac = local_a0 + ((GameObject*)obj)->anim.velocityZ;
    local_44 = lbl_803E3C74;
    local_30 = 3;
    trackDolphin_buildSweptBounds(auStack_9c, &local_a8, &local_b4, &local_b8, 1);
    FUN_80063a74(obj, auStack_9c, 0, '\x01');
    hitFound = FUN_80063a68();
    if (hitFound == 0)
    {
        ((GameObject*)obj)->anim.localPosX = local_b4;
        ((GameObject*)obj)->anim.localPosY = local_b0;
        ((GameObject*)obj)->anim.localPosZ = local_ac;
    }
    else
    {
        *(byte*)(state + 0x92) = *(byte*)(state + 0x92) & 0xfb;
        FUN_80166c6c(obj, state, afStack_84, &local_b4);
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void landedarwing_moveSurfaceCrawler(short* obj, LandedArwingState* state)
{
    int headingAngle;

    objMove((int)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    switch (state->surfaceMode)
    {
    case 0:
        if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
            if ((state->bounceFlags & 0x20) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 5;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
            if ((state->bounceFlags & 0x10) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 4;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
            if ((state->bounceFlags & 4) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 2;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
            if ((state->bounceFlags & 8) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 3;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        break;
    case 1:
        if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
            if ((state->bounceFlags & 0x20) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 5;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
            if ((state->bounceFlags & 0x10) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 4;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
            if ((state->bounceFlags & 4) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 2;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
            if ((state->bounceFlags & 8) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 3;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        break;
    case 2:
        if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
            if ((state->bounceFlags & 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 0;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
            if ((state->bounceFlags & 2) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 1;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
            if ((state->bounceFlags & 0x20) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 5;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
            if ((state->bounceFlags & 0x10) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 4;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        break;
    case 3:
        if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
            if ((state->bounceFlags & 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 0;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
            if ((state->bounceFlags & 2) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 1;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
            if ((state->bounceFlags & 0x20) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 5;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
        {
            ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
            if ((state->bounceFlags & 0x10) != 0)
            {
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityY;
                state->surfaceMode = 4;
            }
            ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        }
        break;
    case 5:
        if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
            if ((state->bounceFlags & 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 0;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
            if ((state->bounceFlags & 2) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 1;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
            if ((state->bounceFlags & 4) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 2;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
            if ((state->bounceFlags & 8) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 3;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        break;
    case 4:
        if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
            if ((state->bounceFlags & 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 0;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
        {
            ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
            if ((state->bounceFlags & 2) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityX;
                state->surfaceMode = 1;
            }
            ((GameObject*)obj)->anim.velocityX = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
            if ((state->bounceFlags & 4) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 2;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        else if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
        {
            ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
            if ((state->bounceFlags & 8) != 0)
            {
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityZ;
                state->surfaceMode = 3;
            }
            ((GameObject*)obj)->anim.velocityZ = lbl_803E2FDC;
        }
        break;
    }

    switch (state->surfaceMode)
    {
    case 0:
        *obj = 0;
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityZ, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = -0x4000;
        break;
    case 1:
        *obj = 0;
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityZ, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = 0x4000;
        break;
    case 2:
        *obj = 0x4000;
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = -0x4000;
        break;
    case 3:
        *obj = 0x4000;
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = 0x4000;
        break;
    case 5:
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        *obj = (short)(headingAngle + 0x8000);
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        break;
    case 4:
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        *obj = (short)(headingAngle + 0x8000);
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = -0x8000;
        break;
    }
    return;
}

#pragma scheduling on
#pragma peephole on
void FUN_801661ec(short* param_1, int param_2)
{
    landedarwing_moveSurfaceCrawler(param_1, (LandedArwingState*)param_2);
}

void FUN_8016693c(int obj, int state)
{
    float stepScale;
    int hitFound;
    int stepCount;
    double distanceRemaining;
    double segmentLen;
    double traveled;
    double one;
    float local_e8;
    float local_e4;
    float local_e0;
    float local_dc;
    float local_d8;
    float local_d4;
    float local_d0;
    uint auStack_cc[6];
    float local_b4;
    float local_b0;
    float local_ac;
    float local_a8;
    float local_74;
    undefined local_60;

    distanceRemaining = FUN_80293900((double)(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
        ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
    traveled = (double)lbl_803E3C74;
    stepCount = 0;
    local_74 = lbl_803E3C74;
    local_60 = 3;
    local_d8 = ((GameObject*)obj)->anim.localPosX;
    local_d4 = ((GameObject*)obj)->anim.localPosY;
    local_d0 = ((GameObject*)obj)->anim.localPosZ;
    local_e4 = local_d8 + ((GameObject*)obj)->anim.velocityX;
    local_e0 = local_d4 + ((GameObject*)obj)->anim.velocityY;
    local_dc = local_d0 + ((GameObject*)obj)->anim.velocityZ;
    local_e8 = lbl_803E3CB8;
    trackDolphin_buildSweptBounds(auStack_cc, &local_d8, &local_e4, &local_e8, 1);
    FUN_80063a74(obj, auStack_cc, 0, '\x01');
    one = (double)lbl_803E3C8C;
    while ((traveled < distanceRemaining && (stepCount = stepCount + 1, stepCount < 10)))
    {
        local_d8 = ((GameObject*)obj)->anim.localPosX;
        local_d4 = ((GameObject*)obj)->anim.localPosY;
        local_d0 = ((GameObject*)obj)->anim.localPosZ;
        stepScale = (float)(one - (double)(float)(traveled / distanceRemaining));
        local_e4 = ((GameObject*)obj)->anim.velocityX * stepScale + local_d8;
        local_e0 = ((GameObject*)obj)->anim.velocityY * stepScale + local_d4;
        local_dc = ((GameObject*)obj)->anim.velocityZ * stepScale + local_d0;
        hitFound = FUN_80063a68();
        if (hitFound == 0)
        {
            ((GameObject*)obj)->anim.localPosX = local_e4;
            ((GameObject*)obj)->anim.localPosY = local_e0;
            ((GameObject*)obj)->anim.localPosZ = local_dc;
            traveled = distanceRemaining;
        }
        else
        {
            segmentLen = FUN_80293900((double)((local_dc - local_d0) * (local_dc - local_d0) +
                (local_e4 - local_d8) * (local_e4 - local_d8) +
                (local_e0 - local_d4) * (local_e0 - local_d4)));
            traveled = (double)(float)(traveled + segmentLen);
            FUN_80166c6c(obj, state, &local_b4, &local_e4);
        }
    }
    local_d8 = ((GameObject*)obj)->anim.localPosX;
    local_d4 = ((GameObject*)obj)->anim.localPosY;
    local_d0 = ((GameObject*)obj)->anim.localPosZ;
    local_e4 = -(lbl_803E3CC0 * *(float*)(state + 0x7c) - local_d8);
    local_e0 = -(lbl_803E3CC0 * *(float*)(state + 0x80) - local_d4);
    local_dc = -(lbl_803E3CC0 * *(float*)(state + 0x84) - local_d0);
    local_74 = lbl_803E3C74;
    local_60 = 3;
    stepCount = FUN_80063a68();
    if (stepCount == 0)
    {
        local_d8 = local_e4;
        local_d4 = local_e0;
        local_d0 = local_dc;
        local_e4 = -((GameObject*)obj)->anim.velocityX;
        local_e0 = -((GameObject*)obj)->anim.velocityY;
        local_dc = -((GameObject*)obj)->anim.velocityZ;
        FUN_80017784(&local_e4);
        local_e4 = lbl_803E3CC4 * local_e4 + local_d8;
        local_e0 = lbl_803E3CC4 * local_e0 + local_d4;
        local_dc = lbl_803E3CC4 * local_dc + local_d0;
        local_74 = lbl_803E3C74;
        local_60 = 3;
        stepCount = FUN_80063a68();
        stepScale = lbl_803E3CC8;
        if (stepCount == 0)
        {
            ((GameObject*)obj)->anim.velocityX = lbl_803E3CC8 * *(float*)(state + 0x7c);
            ((GameObject*)obj)->anim.velocityY = stepScale * *(float*)(state + 0x80);
            ((GameObject*)obj)->anim.velocityZ = stepScale * *(float*)(state + 0x84);
            *(byte*)(state + 0x92) = *(byte*)(state + 0x92) & 0xfb | 4;
        }
        else
        {
            FUN_80166c6c(obj, state, &local_b4, &local_e4);
        }
    }
    else if ((((local_b4 == *(float*)(state + 0x7c)) && (local_b0 == *(float*)(state + 0x80)))
        && (local_ac == *(float*)(state + 0x84))) && (local_a8 == *(float*)(state + 0x88)))
    {
        ((GameObject*)obj)->anim.localPosX = local_e4;
        ((GameObject*)obj)->anim.localPosY = local_e0;
        ((GameObject*)obj)->anim.localPosZ = local_dc;
    }
    else
    {
        FUN_80166c6c(obj, state, &local_b4, &local_e4);
    }
    *(byte*)(state + 0x92) = *(byte*)(state + 0x92) & 0xf7 | 8;
    return;
}

void FUN_80166c6c(int obj, int state, float* plane, float* offset)
{
    float scale;
    double k;
    double surfX;
    double velX;
    double posX;
    double posY;
    double posZ;
    double surfZ;
    double surfY;
    double velZ;
    double velY;
    float local_98;
    float local_94;
    float local_90;
    float local_8c;
    float local_88;
    float local_84;
    float local_80;

    k = (double)lbl_803E3CB8;
    posX = (double)((GameObject*)obj)->anim.localPosX;
    surfX = (double)(float)(k * (double)*(float*)(state + 0x7c) + posX);
    posY = (double)((GameObject*)obj)->anim.localPosY;
    surfY = (double)(float)(k * (double)*(float*)(state + 0x80) + posY);
    posZ = (double)((GameObject*)obj)->anim.localPosZ;
    surfZ = (double)(float)(k * (double)*(float*)(state + 0x84) + posZ);
    velX = (double)(float)(k * (double)((GameObject*)obj)->anim.velocityX + posX);
    velY = (double)(float)(k * (double)((GameObject*)obj)->anim.velocityY + posY);
    k = (double)(float)(k * (double)((GameObject*)obj)->anim.velocityZ + posZ);
    velZ = (double)(float)(posY * (double)(float)(surfZ - k) +
        (double)(float)(surfY * (double)(float)(k - posZ) +
            (double)(float)(velY * (double)(float)(posZ - surfZ))));
    posZ = (double)(float)(posZ * (double)(float)(surfX - velX) +
        (double)(float)(surfZ * (double)(float)(velX - posX) +
            (double)(float)(k * (double)(float)(posX - surfX))));
    velX = (double)(float)(posX * (double)(float)(surfY - velY) +
        (double)(float)(surfX * (double)(float)(velY - posY) +
            (double)(float)(velX * (double)(float)(posY - surfY))));
    k = FUN_80293900((double)(float)(velX * velX +
        (double)(float)(velZ * velZ +
            (double)(float)(posZ * posZ))));
    if ((double)lbl_803E3C74 < k)
    {
        k = (double)(float)((double)lbl_803E3C8C / k);
        velZ = (double)(float)(velZ * k);
        posZ = (double)(float)(posZ * k);
        velX = (double)(float)(velX * k);
    }
    local_98 = (float)velZ;
    local_94 = (float)posZ;
    local_90 = (float)velX;
    local_8c = -(float)(surfZ * velX +
        (double)(float)(surfX * velZ + (double)(float)(surfY * posZ)));
    FUN_80017788(&local_98, plane, &local_88);
    FUN_80017784(&local_88);
    scale = lbl_803E3C9C;
    ((GameObject*)obj)->anim.velocityX = lbl_803E3C9C * local_88;
    ((GameObject*)obj)->anim.velocityY = scale * local_84;
    ((GameObject*)obj)->anim.velocityZ = scale * local_80;
    *(float*)(state + 0x7c) = *plane;
    *(float*)(state + 0x80) = plane[1];
    *(float*)(state + 0x84) = plane[2];
    *(float*)(state + 0x88) = plane[3];
    ((GameObject*)obj)->anim.localPosX = *offset + *(float*)(state + 0x7c);
    ((GameObject*)obj)->anim.localPosY = offset[1] + *(float*)(state + 0x80);
    ((GameObject*)obj)->anim.localPosZ = offset[2] + *(float*)(state + 0x84);
    return;
}

void dll_D3_hitDetect_nop(void)
{
}

int dll_D3_getExtraSize_ret_1188(void) { return 0x4a4; }
int dll_D3_getObjectTypeId(void) { return 0x49; }

extern int* gBaddieControlInterface;
#pragma scheduling off
#pragma peephole off
void dll_D3_free(int obj)
{
    int* inner = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
        *(int*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    (*(void (*)(int, int*, int))(*(int*)(*gBaddieControlInterface + 0x40)))(obj, inner, 0);
}

extern void Vec3_Normalize(f32 * v);
extern void Vec3_Cross(f32 * a, f32 * b, f32 * out);

typedef struct StaffBits
{
    u8 hi : 4;
    u8 b3 : 1;
    u8 b2 : 1;
    u8 lo : 2;
} StaffBits;
#pragma dont_inline on
#pragma peephole on
void fn_80166E38(f32* out, f32* forward, f32* up)
{
    f32 rt[3];
    f32 upRecomputed[3];
    f32 fwd[3];
    fwd[0] = forward[0];
    fwd[1] = forward[1];
    fwd[2] = forward[2];
    Vec3_Normalize(fwd);
    Vec3_Cross(up, fwd, rt);
    Vec3_Normalize(rt);
    Vec3_Cross(rt, fwd, upRecomputed);
    Vec3_Normalize(upRecomputed);
    {
        f32(*mat)[4] = (f32 (*)[4])out;
        mat[0][0] = -rt[0];
        mat[0][1] = -rt[1];
        mat[0][2] = -rt[2];
        mat[1][0] = -upRecomputed[0];
        mat[1][1] = -upRecomputed[1];
        mat[1][2] = -upRecomputed[2];
        mat[2][0] = -fwd[0];
        mat[2][1] = -fwd[1];
        mat[2][2] = -fwd[2];
    }
}
#pragma dont_inline reset

#pragma peephole off
void dll_D3_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    int state;
    f32* slideMtx;
    f32 mtx[15];
    f32 scale;

    state = (int)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    slideMtx = (f32*)(state + 4);
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
        if ((((LandedArwingState*)state)->surfaceMode == 6) && ((((u32)((LandedArwingState*)state)->flags92 >> 3) & 1) != 0))
        {
            if ((((u32)((LandedArwingState*)state)->flags92 >> 2) & 1) == 0)
            {
                fn_80166E38(slideMtx, &((GameObject*)obj)->anim.velocityX, (f32*)(state + 0x7c));
            }
            scale = ((GameObject*)obj)->anim.rootMotionScale;
            initRotationMtx(mtx, scale, scale, scale);
            mtx44_mult(mtx, slideMtx, mtx);
            mtx[12] = ((GameObject*)obj)->anim.localPosX - playerMapOffsetX;
            mtx[13] = ((GameObject*)obj)->anim.localPosY;
            mtx[14] = ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ;
            fn_8003B950(mtx);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E2FF4);
            fn_8003B950(0);
        }
        else
        {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E2FF4);
        }
            break;
        }
    }
}

undefined4 fn_801659B8(s16* obj, u32* params)
{
    LandedArwingState* state;

    state = *(LandedArwingState**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(undefined*)((int)params + 0x34d) = 1;
    if (*(s8*)((int)params + 0x27a) != 0)
    {
        state->speed = lbl_803E3004;
        ObjHits_EnableObject((u32)obj);
        ((GameObject*)obj)->anim.velocityX = -(state->speed) * fsin16Precise((u16) * obj);
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FDC;
        ((GameObject*)obj)->anim.velocityZ = -(state->speed) * fcos16Precise((u16) * obj);
        *params |= 0x2004000;
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2FDC, 0);
        state->animSpeed = lbl_803E2FDC;
    }
    ObjHits_SetHitVolumeSlot((u32)obj, 9, 1, -1);
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6c) = 9;
    *(undefined*)(*(int*)(obj + 0x2a) + 0x6d) = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    (*gPathControlInterface)->advance(obj, params + 1, timeDelta);
    if (*(s8*)((int)params + 0x27a) != 0)
    {
        if (*(s8*)&state->surfaceMode == 6)
        {
            if (((state->flags92 >> 2) & 1) == 0)
            {
                fn_80166444((int)obj, (int)state);
            }
            else
            {
                fn_80165B3C((int)obj, (int)state);
            }
        }
        else
        {
            landedarwing_moveSurfaceCrawler(obj, state);
        }
    }
    return 0;
}

void fn_80165B3C(int obj, int state)
{
    f32 radius;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 start[3];
    f32 end[3];
    uint bounds[6];
    struct
    {
        f32 hit[16];
        f32 hitRadius;
        undefined pad[0x10];
        undefined hitType;
        undefined pad2[0x1f];
    } hitScratch;
    f32 damping;
    int hitFound;

    radius = lbl_803E3020;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E2FF4;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (damping = lbl_803E3024);
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * damping;
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * damping;
    start[0] = ((GameObject*)obj)->anim.localPosX;
    start[1] = ((GameObject*)obj)->anim.localPosY;
    start[2] = ((GameObject*)obj)->anim.localPosZ;
    end[0] = start[0] + ((GameObject*)obj)->anim.velocityX;
    end[1] = start[1] + ((GameObject*)obj)->anim.velocityY;
    end[2] = start[2] + ((GameObject*)obj)->anim.velocityZ;
    hitScratch.hitRadius = lbl_803E2FDC;
    hitScratch.hitType = 3;
    hitDetect_calcSweptSphereBounds(bounds, start, end, &radius, 1);
    hitDetectFn_800691c0(obj, bounds, 0, 1);
    hitFound = hitDetectFn_80067958(obj, start, end, 1, hitScratch.hit, 0x20);
    if (hitFound != 0)
    {
        {
            struct StaffFlag92
            {
                u8 b80 : 1, b40 : 1, b20 : 1, b10 : 1, b08 : 1, b04 : 1, b02 : 1, b01 : 1;
            };
            int zero = 0;
            ((struct StaffFlag92*)&((LandedArwingState*)state)->flags92)->b04 = zero;
        }
        fn_80166840(obj, state, hitScratch.hit, end);
    }
    else
    {
        ((GameObject*)obj)->anim.localPosX = end[0];
        ((GameObject*)obj)->anim.localPosY = end[1];
        ((GameObject*)obj)->anim.localPosZ = end[2];
    }
}

void fn_80166840(int obj, int state, f32* hit, f32* end)
{
    f32 fVar1;
    f32 planeX;
    f32 planeY;
    f32 planeZ;
    f32 planeW;
    f32 response[3];
    f32 plane[4];
    f32 scale;
    f32 objX;
    f32 objY;
    f32 objZ;
    f32 stateX;
    f32 stateY;
    f32 stateZ;
    f32 velX;
    f32 velY;
    f32 velZ;
    f32 len;

    scale = lbl_803E3020;
    stateX = scale * ((LandedArwingState*)state)->surfaceNormalX + ((GameObject*)obj)->anim.localPosX;
    objX = ((GameObject*)obj)->anim.localPosX;
    stateY = scale * ((LandedArwingState*)state)->surfaceNormalY + ((GameObject*)obj)->anim.localPosY;
    objY = ((GameObject*)obj)->anim.localPosY;
    stateZ = scale * ((LandedArwingState*)state)->surfaceNormalZ + ((GameObject*)obj)->anim.localPosZ;
    objZ = ((GameObject*)obj)->anim.localPosZ;
    velX = scale * ((GameObject*)obj)->anim.velocityX + objX;
    velY = scale * ((GameObject*)obj)->anim.velocityY + objY;
    velZ = scale * ((GameObject*)obj)->anim.velocityZ + objZ;
    planeX = objY * (stateZ - velZ) + (stateY * (velZ - objZ) + velY * (objZ - stateZ));
    planeY = objZ * (stateX - velX) + (stateZ * (velX - objX) + velZ * (objX - stateX));
    planeZ = objX * (stateY - velY) + (stateX * (velY - objY) + velX * (objY - stateY));
    len = sqrtf(planeX * planeX + (planeY * planeY + planeZ * planeZ));
    if (len > lbl_803E2FDC)
    {
        len = lbl_803E2FF4 / len;
        planeX *= len;
        planeY *= len;
        planeZ *= len;
    }
    planeW = -(stateZ * planeZ + (stateX * planeX + stateY * planeY));
    plane[0] = planeX;
    plane[1] = planeY;
    plane[2] = planeZ;
    plane[3] = planeW;
    Vec3_Cross(plane, hit, response);
    Vec3_Normalize(response);
    fVar1 = lbl_803E3004;
    ((GameObject*)obj)->anim.velocityX = lbl_803E3004 * response[0];
    ((GameObject*)obj)->anim.velocityY = fVar1 * response[1];
    ((GameObject*)obj)->anim.velocityZ = fVar1 * response[2];
    ((LandedArwingState*)state)->surfaceNormalX = hit[0];
    ((LandedArwingState*)state)->surfaceNormalY = hit[1];
    ((LandedArwingState*)state)->surfaceNormalZ = hit[2];
    ((LandedArwingState*)state)->surfacePlaneD = hit[3];
    ((GameObject*)obj)->anim.localPosX = end[0] + ((LandedArwingState*)state)->surfaceNormalX;
    ((GameObject*)obj)->anim.localPosY = end[1] + ((LandedArwingState*)state)->surfaceNormalY;
    ((GameObject*)obj)->anim.localPosZ = end[2] + ((LandedArwingState*)state)->surfaceNormalZ;
}

void updateConstrainedChaseVelocity(int obj, f32 targetX, f32 targetY, f32 targetZ, f32 blend)
{
    LandedArwingState* state;
    int mode;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 len;
    f32 scale;
    f32 dot;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    if ((u32)(state->flags92 >> 2 & 1) == 0)
    {
        vx = targetX - ((GameObject*)obj)->anim.localPosX;
        vy = targetY - ((GameObject*)obj)->anim.localPosY;
        vz = targetZ - ((GameObject*)obj)->anim.localPosZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (len >= lbl_803E2FDC)
        {
            scale = state->speed / len;
            vx *= scale;
            vy *= scale;
            vz *= scale;
        }
        vx = blend * (vx - ((GameObject*)obj)->anim.velocityX) + ((GameObject*)obj)->anim.velocityX;
        vy = blend * (vy - ((GameObject*)obj)->anim.velocityY) + ((GameObject*)obj)->anim.velocityY;
        vz = blend * (vz - ((GameObject*)obj)->anim.velocityZ) + ((GameObject*)obj)->anim.velocityZ;
        mode = state->surfaceMode;
        switch (mode)
        {
        case 0:
        case 1:
            vx = 0.0f;
            len = sqrtf(vy * vy + vz * vz);
            if (len != lbl_803E2FDC)
            {
                scale = state->speed / len;
                vy *= scale;
                vz *= scale;
            }
            break;
        case 2:
        case 3:
            vz = 0.0f;
            len = sqrtf(vx * vx + vy * vy);
            if (len != lbl_803E2FDC)
            {
                scale = state->speed / len;
                vx *= scale;
                vy *= scale;
            }
            break;
        case 4:
        case 5:
            vy = 0.0f;
            len = sqrtf(vx * vx + vz * vz);
            if (len != lbl_803E2FDC)
            {
                scale = state->speed / len;
                vx *= scale;
                vz *= scale;
            }
            break;
        case 6:
            dot = vz * state->surfaceNormalZ +
                (vx * state->surfaceNormalX + vy * state->surfaceNormalY);
            vx = -(dot * state->surfaceNormalX - vx);
            vy = -(dot * state->surfaceNormalY - vy);
            vz = -(dot * state->surfaceNormalZ - vz);
            len = sqrtf(vz * vz + (vx * vx + vy * vy));
            if (len != lbl_803E2FDC)
            {
                scale = state->speed / len;
                vx *= scale;
                vy *= scale;
                vz *= scale;
            }
            break;
        }
        ((GameObject*)obj)->anim.velocityX = vx;
        ((GameObject*)obj)->anim.velocityY = vy;
        ((GameObject*)obj)->anim.velocityZ = vz;
    }
}

void fn_80166444(int obj, int state)
{
    f32 one;
    f32 distanceRemaining;
    int hitFound;
    int stepCount;
    f32 traveled;
    f32 segmentLen;
    f32 stepScale;
    f32 radius;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 start[3];
    f32 end[3];
    uint bounds[6];
    struct
    {
        f32 hit[16];
        f32 hitRadius;
        undefined pad[0x10];
        undefined hitType;
    } hitScratch;
    f32 fVar1;

    distanceRemaining = sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
        (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
    traveled = lbl_803E2FDC;
    stepCount = 0;
    hitScratch.hitRadius = traveled;
    hitScratch.hitType = 3;
    start[0] = ((GameObject*)obj)->anim.localPosX;
    start[1] = ((GameObject*)obj)->anim.localPosY;
    start[2] = ((GameObject*)obj)->anim.localPosZ;
    end[0] = start[0] + ((GameObject*)obj)->anim.velocityX;
    end[1] = start[1] + ((GameObject*)obj)->anim.velocityY;
    end[2] = start[2] + ((GameObject*)obj)->anim.velocityZ;
    radius = lbl_803E3020;
    hitDetect_calcSweptSphereBounds(bounds, start, end, &radius, 1);
    hitDetectFn_800691c0(obj, bounds, 0, 1);
    one = lbl_803E2FF4;
    while ((traveled < distanceRemaining) && (++stepCount < 10))
    {
        start[0] = ((GameObject*)obj)->anim.localPosX;
        start[1] = ((GameObject*)obj)->anim.localPosY;
        start[2] = ((GameObject*)obj)->anim.localPosZ;
        stepScale = one - (traveled / distanceRemaining);
        end[0] = ((GameObject*)obj)->anim.velocityX * stepScale + start[0];
        end[1] = ((GameObject*)obj)->anim.velocityY * stepScale + start[1];
        end[2] = ((GameObject*)obj)->anim.velocityZ * stepScale + start[2];
        hitFound = hitDetectFn_80067958(obj, start, end, 1, hitScratch.hit, 0x20);
        if (hitFound != 0)
        {
            dx = end[0] - start[0];
            dy = end[1] - start[1];
            dz = end[2] - start[2];
            segmentLen = sqrtf(dz * dz + (dx * dx + dy * dy));
            traveled = (f32)(traveled + segmentLen);
            fn_80166840(obj, state, hitScratch.hit, end);
        }
        else
        {
            traveled = distanceRemaining;
            ((GameObject*)obj)->anim.localPosX = end[0];
            ((GameObject*)obj)->anim.localPosY = end[1];
            ((GameObject*)obj)->anim.localPosZ = end[2];
        }
    }
    start[0] = ((GameObject*)obj)->anim.localPosX;
    start[1] = ((GameObject*)obj)->anim.localPosY;
    start[2] = ((GameObject*)obj)->anim.localPosZ;
    end[0] = -(*(f32*)&lbl_803E3028 * ((LandedArwingState*)state)->surfaceNormalX - start[0]);
    end[1] = -(*(f32*)&lbl_803E3028 * ((LandedArwingState*)state)->surfaceNormalY - start[1]);
    end[2] = -(*(f32*)&lbl_803E3028 * ((LandedArwingState*)state)->surfaceNormalZ - start[2]);
    hitScratch.hitRadius = lbl_803E2FDC;
    hitScratch.hitType = 3;
    hitFound = hitDetectFn_80067958(obj, start, end, 1, hitScratch.hit, 0x20);
    if (hitFound != 0)
    {
        if ((((hitScratch.hit[0] != ((LandedArwingState*)state)->surfaceNormalX) ||
                    (hitScratch.hit[1] != ((LandedArwingState*)state)->surfaceNormalY)) ||
                (hitScratch.hit[2] != ((LandedArwingState*)state)->surfaceNormalZ)) ||
            (hitScratch.hit[3] != ((LandedArwingState*)state)->surfacePlaneD))
        {
            fn_80166840(obj, state, hitScratch.hit, end);
        }
        else
        {
            ((GameObject*)obj)->anim.localPosX = end[0];
            ((GameObject*)obj)->anim.localPosY = end[1];
            ((GameObject*)obj)->anim.localPosZ = end[2];
        }
    }
    else
    {
        start[0] = end[0];
        start[1] = end[1];
        start[2] = end[2];
        end[0] = -((GameObject*)obj)->anim.velocityX;
        end[1] = -((GameObject*)obj)->anim.velocityY;
        end[2] = -((GameObject*)obj)->anim.velocityZ;
        Vec3_Normalize(end);
        end[0] = lbl_803E302C * end[0] + start[0];
        end[1] = lbl_803E302C * end[1] + start[1];
        end[2] = lbl_803E302C * end[2] + start[2];
        hitScratch.hitRadius = lbl_803E2FDC;
        hitScratch.hitType = 3;
        hitFound = hitDetectFn_80067958(obj, start, end, 1, hitScratch.hit, 0x20);
        if (hitFound != 0)
        {
            fn_80166840(obj, state, hitScratch.hit, end);
        }
        else
        {
            fVar1 = lbl_803E3030;
            ((GameObject*)obj)->anim.velocityX = fVar1 * ((LandedArwingState*)state)->surfaceNormalX;
            ((GameObject*)obj)->anim.velocityY = fVar1 * ((LandedArwingState*)state)->surfaceNormalY;
            ((GameObject*)obj)->anim.velocityZ = fVar1 * ((LandedArwingState*)state)->surfaceNormalZ;
            ((StaffBits*)&((LandedArwingState*)state)->flags92)->b2 = 1;
        }
    }
    ((StaffBits*)&((LandedArwingState*)state)->flags92)->b3 = 1;
}

/* segment pragma-stack balance (re-split): */

#include "main/dll/treasurechest_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/object_descriptor.h"

typedef struct DllD3Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2E - 0x14];
    u8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllD3Placement;

extern void* Obj_GetPlayerObject(void);
extern int ObjContact_AddCallback(int* obj, int p2, void* cb);
extern int ObjList_FindNearestObjectByDefNo(int* obj, int defNo, f32* radius);
extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, int* out, int* obj, int e, int g, int h, int i);
extern f32 sqrtf(f32);
extern void* memset(void* dst, int val, u32 size);
extern int* gPlayerInterface;

extern int lbl_803202E8[];
extern int lbl_80320360[];
extern int lbl_803AC638[];
extern void* gLandedArwingStateHandlers[];
extern void* gLandedArwingDefaultStateHandler;

extern double lbl_803E3040;
extern f32 lbl_803E3034;
extern f32 lbl_803E3038;
extern f32 lbl_803E3048;

extern void LandedArwing_UpdateRetreatChase(void);
extern void LandedArwing_UpdateBounceFade(void);
extern void LandedArwing_TriggerLaunchTarget(void);
extern void LandedArwing_ReturnZero(void);

extern void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte);
extern void fn_80167550(int* obj);

#pragma fp_contract off
void dll_D3_update(int* obj)
{
    int trans;
    int* state;
    LandedArwingState* extra;
    int* player;
    int hitCount;
    int rc;
    int hits;
    struct { f32 searchRadius; f32 x, y, z; } sd;
    int aiStack_80[22];
    char hitType;

    trans = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    extra = *(LandedArwingState**)((char*)state + 0x40c);
    player = (int*)Obj_GetPlayerObject();
    sd.searchRadius = lbl_803E3034;

    if (extra->boundsObj == NULL)
    {
        extra->surfaceMode = 6;
        if (((u32)extra->flags92 >> 4 & 0xF) != 0u)
        {
            hits = ObjList_FindNearestObjectByDefNo(obj, 0x4ad, &sd.searchRadius);
            *(int*)&extra->boundsObj = hits;
            if ((void*)hits != NULL)
            {
                (*(void (**)(int, int, int))(*(int**)(*(int*)(*(int*)&extra->boundsObj + 0x68)) + 0x20 / 4))(
                    *(int*)&extra->boundsObj,
                    (int)&extra->boundsMinX,
                    (int)&extra->bounceFlags);
                extra->surfaceMode = 5;
            }
            ((StaffBits*)&extra->flags92)->hi -= 1;
        }
    }

    if (((GameObject*)obj)->unkF4 != 0) return;

    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((DllD3Placement*)trans)->unk8;
        ((GameObject*)obj)->anim.localPosY = ((DllD3Placement*)trans)->unkC;
        ((GameObject*)obj)->anim.localPosZ = ((DllD3Placement*)trans)->unk10;
        (*gObjectTriggerInterface)->runSequence(*(s8*)((char*)trans + 0x2e), obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }

    rc = ((int (*)(int*, int*, int))((void**)*(int*)gBaddieControlInterface)[0x30 / 4])(obj, state, 0);
    if (rc == 0) return;

    if ((extra->flags92 >> 1 & 1) == 0u)
    {
        if (ObjContact_AddCallback(obj, (int)player, fn_80167550) != 0)
        {
            struct StaffFlag92b
            {
                u8 b80 : 1, b40 : 1, b20 : 1, b10 : 1, b08 : 1, b04 : 1, b02 : 1, b01 : 1;
            };
            ((struct StaffFlag92b*)&extra->flags92)->b02 = 1;
        }
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, extra->animSpeed, timeDelta, NULL);

    if (((TreasureChestState*)state)->targetState != 1)
    {
        rc = ((int (*)(int*, int*, f32, int))((void**)*(int*)gBaddieControlInterface)[0x48 / 4])(
            obj, state,
            (f32)(u32)((TreasureChestState*)state)->aggroRange, 0x8000);
        if (rc != 0u)
        {
            ((void (*)(int*, int*, int, int, int, int, int, int, int))((void**)*(int*)gBaddieControlInterface)[0x28 /
                4])(
                obj, state,
                (int)state + 0x35c,
                (int)((TreasureChestState*)state)->gameBitB,
                0, 0, 1, 0, -1);
            ((TreasureChestState*)state)->targetObj = rc;
            ((TreasureChestState*)state)->unk349 = 0;
            ((TreasureChestState*)state)->targetState = 1;
            ((TreasureChestState*)state)->unk405 = 2;
        }
    }

    if ((void*)((TreasureChestState*)state)->targetObj != NULL &&
        ((TreasureChestState*)state)->targetState == 2)
    {
        if (((TreasureChestState*)state)->targetDistance <=
            (f32)(u32)((TreasureChestState*)state)->aggroRange)
        {
            ((TreasureChestState*)state)->targetState = 1;
        }
    }

    if (((TreasureChestState*)state)->targetObj != 0u)
    {
        sd.x = *(f32*)((char*)(((TreasureChestState*)state)->targetObj) + 0x18) -
            ((GameObject*)obj)->anim.worldPosX;
        sd.y = *(f32*)((char*)(((TreasureChestState*)state)->targetObj) + 0x1c) -
            ((GameObject*)obj)->anim.worldPosY;
        sd.z = *(f32*)((char*)(((TreasureChestState*)state)->targetObj) + 0x20) -
            ((GameObject*)obj)->anim.worldPosZ;
        ((TreasureChestState*)state)->targetDistance =
            sqrtf(sd.x * sd.x + sd.y * sd.y + sd.z * sd.z);
    }

    ((void (*)(int*, int*, int, int, int, int, int, int))((void**)*(int*)gBaddieControlInterface)[0x54 / 4])(
        obj, state,
        (int)((char*)state + 0x35c),
        (int)((TreasureChestState*)state)->gameBitB,
        0, 0, 0, 0);

    hits = (int)((TreasureChestState*)state)->hitPoints;
    if (hits > 0)
    {
        ((void (*)(int*, int*, int, int, int*, int*, int, int*))((void**)*(int*)gBaddieControlInterface)[0x50 / 4])(
            obj, state,
            (int)((char*)state + 0x35c),
            (int)((TreasureChestState*)state)->gameBitB,
            lbl_803202E8, lbl_80320360, 0, lbl_803AC638);
        if ((int)((TreasureChestState*)state)->hitPoints < hits)
        {
            (*(void (**)(void))(*(int**)(*(int*)&((GameObject*)player)->childObjs[0] + 0x68) + 0x50 / 4))();
            *(f32*)((char*)lbl_803AC638 + 0xc) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)lbl_803AC638 + 0x10) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)lbl_803AC638 + 0x14) = ((GameObject*)obj)->anim.localPosZ;
            objLightFn_8009a1dc(obj, lbl_803E3038, lbl_803AC638, 1, 0);
        }
    }

    ((void (*)(int*, int*, f32, int))((void**)*(int*)gBaddieControlInterface)[0x2c / 4])(
        obj, state, lbl_803E2FDC, -1);

    ((TreasureChestState*)state)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;

    ((void (*)(f32, f32, int*, int*, void**, void*))((void**)*(int*)gPlayerInterface)[8 / 4])(
        timeDelta, timeDelta, obj, state, gLandedArwingStateHandlers, &gLandedArwingDefaultStateHandler);

    *(int*)&((GameObject*)obj)->pendingParentObj = ((TreasureChestState*)state)->savedObjC0;

    if ((extra->flags92 & 1) == 0 &&
        extra->surfaceMode == 6)
    {
        hitCount = objBboxFn_800640cc(
            (int)((char*)obj + 0x80),
            &((GameObject*)obj)->anim.localPosX,
            lbl_803E3030, 0,
            aiStack_80, obj, -0x7c, -1, 0xff, 0);
        if (hitCount != 0 && hitType == 13)
        {
            extra->flags92 =
                (u8)((extra->flags92 & 0xfe) | 1);
            *(s16*)&extra->scriptTimer = (s16)(randomGetRange(10, 0xf) * 0x3c);
        }
    }
}
#pragma fp_contract reset

void dll_D3_init(int obj, int def, int flag)
{
    int state;
    LandedArwingState* extra;
    u8 setupFlags;
    f32 fz;
    int ftag;

    state = *(int*)&((GameObject*)obj)->extra;
    setupFlags = 6;
    if (flag != 0)
    {
        setupFlags |= 1;
    }
    ((void (*)(int, int, int, int, int, int, u8, f32))((void**)*(int*)gBaddieControlInterface)[22])
        (obj, def, state, 5, 1, 0x108, setupFlags, lbl_803E3048);
    ((GameObject*)obj)->animEventCallback = NULL;

    extra = *(LandedArwingState**)(state + 0x40c);
    memset((void*)extra, 0, 0x94);
    extra->surfaceMode = 5;
    ((StaffBits*)&extra->flags92)->hi = 3;
    fz = lbl_803E2FDC;
    extra->surfaceNormalX = fz;
    extra->surfaceNormalY = lbl_803E2FF4;
    extra->surfaceNormalZ = fz;
    extra->surfacePlaneD = -((GameObject*)obj)->anim.localPosY;
    extra->scriptTargetX = ((GameObject*)obj)->anim.localPosX;
    extra->scriptTargetY = ((GameObject*)obj)->anim.localPosY;
    extra->scriptTargetZ = ((GameObject*)obj)->anim.localPosZ;

    ObjAnim_SetCurrentMove(obj, 0, fz, 0);
    if (*(u8*)(def + 0x2b) == 0)
    {
        ftag = 0;
    }
    else
    {
        ftag = 1;
    }
    ((TreasureChestState*)state)->controlMode = ftag;
    ((TreasureChestState*)state)->unk270 = 0;
    ((TreasureChestState*)state)->targetState = 0;
    ((TreasureChestState*)state)->unk405 = 0;
    ((TreasureChestState*)state)->unk25F = 0;
    ObjHits_DisableObject((u32)obj);

    fz = lbl_803E2FF4;
    extra->unk_04 = fz;
    extra->unk_18 = fz;
    extra->unk_2C = fz;
    extra->unk_40 = fz;
}

void dll_D3_initialise(void)
{
    extern void fn_801659B8(void); /* #57 */
    gLandedArwingStateHandlers[0] = fn_801659B8;
    gLandedArwingStateHandlers[1] = LandedArwing_UpdateFlightChase;
    gLandedArwingStateHandlers[2] = LandedArwing_UpdateRetreatChase;
    gLandedArwingStateHandlers[3] = LandedArwing_UpdateBounceFade;
    gLandedArwingStateHandlers[4] = LandedArwing_TriggerLaunchTarget;
    gLandedArwingDefaultStateHandler = LandedArwing_ReturnZero;
}

void dll_D3_release_nop(void)
{
}

void skeetlawall_free(void);

void skeetlawall_hitDetect(void);

void skeetlawall_update(void);

void skeetlawall_release(void);

void skeetlawall_initialise(void);

int skeetlawall_getExtraSize(void);
int skeetlawall_getObjectTypeId(void);

void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void skeetlawall_init(int obj, u8* def);

ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)skeetlawall_initialise,
        (ObjectDescriptorCallback)skeetlawall_release,
        0,
        (ObjectDescriptorCallback)skeetlawall_init,
        (ObjectDescriptorCallback)skeetlawall_update,
        (ObjectDescriptorCallback)skeetlawall_hitDetect,
        (ObjectDescriptorCallback)skeetlawall_render,
        (ObjectDescriptorCallback)skeetlawall_free,
        (ObjectDescriptorCallback)skeetlawall_getObjectTypeId,
        skeetlawall_getExtraSize,
        (ObjectDescriptorCallback)skeetlawall_setScale,
    },
    0,
};

void fn_80167550(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    ((void (*)(int*, int*, int))((void**)*gPlayerInterface)[5])(obj, state, 2);
}

void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte);
