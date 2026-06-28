/*
 * staffAction (DLL 0x00D3) - a baddie that hops/crawls along surfaces and
 * chases the player, driven by the shared baddie-control interface
 * (gBaddieControlInterface) and the LandedArwing movement/collision state
 * (LandedArwingState behind GroundBaddieState->control, at +0x40c).
 *
 * Movement is a bounce-walker: landedarwing_moveSurfaceCrawler runs a
 * per-axis bounce machine over surfaceMode 0-5 (X/Y/Z wall planes), while
 * surfaceMode 6 is the swept-surface mode that does collision against a
 * bound mesh object (fn_80165B3C / fn_80166444 / fn_80166840). flags92
 * is a packed bit/nibble field (StaffBits) holding the per-frame movement
 * flags and a retry counter (hi nibble).
 *
 * dll_D3_update drives target acquisition, contact damage, and per-frame
 * advance through gBaddieControlInterface and gPlayerInterface vtable
 * slots; the object id is 0x49 and its extra block is 0x4a4 bytes. The
 * state handler table gLandedArwingStateHandlers is populated in
 * dll_D3_initialise (slot 0 = fn_801659B8).
 *
 * The TU also defines a second object descriptor, gSkeetlaWallObjDescriptor
 * (skeetlawall), an 11-slot object whose callbacks live in a sibling unit.
 */
#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/dll/landedArwing.h"
#include "main/dll/dll_00D3_staffAction.h"
#include "main/objhits.h"
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
extern void mtx44_mult(f32* a, f32* b, f32* out);
extern void fn_8003B950(void* mtx);
extern int hitDetectFn_80067958(int obj, f32* startPoints, f32* endPoints, int pointCount,
                                void* hits, int hitCount);
extern void hitDetectFn_800691c0(int obj, void* bounds, u32 mask, int flags);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, float* startPoints, float* endPoints, float* radii,
                                            int pointCount);
extern float fsin16Precise(int angle);
extern float fcos16Precise(int angle);
extern f32 sqrtf(f32 x);
extern int* gBaddieControlInterface;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern const f32 lbl_803E2FDC;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E3004;
extern f32 lbl_803E3020;
extern f32 gStaffActionVelocityDamping;
extern f32 lbl_803E3028;
extern f32 lbl_803E302C;
extern f32 lbl_803E3030;

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
        *obj = 0; /* rotX */
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityZ, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = -0x4000;
        break;
    case 1:
        *obj = 0; /* rotX */
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityZ, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = 0x4000;
        break;
    case 2:
        *obj = 0x4000; /* rotX */
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = -0x4000;
        break;
    case 3:
        *obj = 0x4000; /* rotX */
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.rotY = (short)(headingAngle + 0x4000);
        ((GameObject*)obj)->anim.rotZ = 0x4000;
        break;
    case 5:
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        *obj = (short)(headingAngle + 0x8000); /* rotX */
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        break;
    case 4:
        headingAngle = atan2_8002178c(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        *obj = (short)(headingAngle + 0x8000); /* rotX */
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = -0x8000;
        break;
    }
    return;
}

#pragma scheduling on
#pragma peephole on
void dll_D3_hitDetect_nop(void)
{
}

int dll_D3_getExtraSize_ret_1188(void) { return 0x4a4; }
int dll_D3_getObjectTypeId(void) { return 0x49; }

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
    u8 b1 : 1;
    u8 b0 : 1;
} StaffBits;
#pragma dont_inline on
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

u32 fn_801659B8(s16* obj, u32* params)
{
    LandedArwingState* state;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    *(u8*)((int)params + 0x34d) = 1;
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
    *(u8*)(*(int*)&((GameObject*)obj)->anim.hitReactState + 0x6c) = 9;
    *(u8*)(*(int*)&((GameObject*)obj)->anim.hitReactState + 0x6d) = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    (*gPathControlInterface)->advance(obj, params + 1, timeDelta);
    if (*(s8*)((int)params + 0x27a) != 0)
    {
        if (state->surfaceMode == 6)
        {
            if (((state->flags92 >> 2) & 1) != 0u)
            {
                fn_80165B3C((int)obj, (int)state);
            }
            else
            {
                fn_80166444((int)obj, (int)state);
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
    u32 bounds[6];
    struct
    {
        f32 hit[16];
        f32 hitRadius;
        u8 pad[0x10];
        u8 hitType;
        u8 pad2[0x1f];
    } hitScratch;
    f32 damping;
    int hitFound;

    radius = lbl_803E3020;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E2FF4;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (damping = gStaffActionVelocityDamping);
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
            int zero = 0;
            ((StaffBits*)&((LandedArwingState*)state)->flags92)->b2 = zero;
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
    f32 speed;
    f32 planeX;
    f32 planeZ;
    f32 planeY;
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
    len = sqrtf(planeZ * planeZ + (planeX * planeX + planeY * planeY));
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
    speed = lbl_803E3004;
    ((GameObject*)obj)->anim.velocityX = lbl_803E3004 * response[0];
    ((GameObject*)obj)->anim.velocityY = speed * response[1];
    ((GameObject*)obj)->anim.velocityZ = speed * response[2];
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
    u32 bounds[6];
    struct
    {
        f32 hit[16];
        f32 hitRadius;
        u8 pad[0x10];
        u8 hitType;
        u8 pad2[0x10];
    } hitScratch;
    f32 speed;

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
    end[1] = -(lbl_803E3028 * ((LandedArwingState*)state)->surfaceNormalY - start[1]);
    end[2] = -(lbl_803E3028 * ((LandedArwingState*)state)->surfaceNormalZ - start[2]);
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
            speed = lbl_803E3030;
            ((GameObject*)obj)->anim.velocityX = speed * ((LandedArwingState*)state)->surfaceNormalX;
            ((GameObject*)obj)->anim.velocityY = speed * ((LandedArwingState*)state)->surfaceNormalY;
            ((GameObject*)obj)->anim.velocityZ = speed * ((LandedArwingState*)state)->surfaceNormalZ;
            ((StaffBits*)&((LandedArwingState*)state)->flags92)->b2 = 1;
        }
    }
    ((StaffBits*)&((LandedArwingState*)state)->flags92)->b3 = 1;
}

#include "main/dll/treasurechest_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/object_descriptor.h"
#include "main/gameplay_runtime.h"
#include "string.h"

typedef struct DllD3Placement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x2E - 0x14];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllD3Placement;

extern int ObjContact_AddCallback(int* obj, int p2, void* cb);
extern int ObjList_FindNearestObjectByDefNo(int* obj, int defNo, f32* radius);
extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, int* out, int* obj, int e, int g, int h, int i);
extern int* gPlayerInterface;
extern int lbl_803202E8[];
extern int lbl_80320360[];
extern int gStaffActionHitLightParams[];
extern void* gLandedArwingStateHandlers[];
extern void* gLandedArwingDefaultStateHandler;
extern f32 gStaffActionBoundsSearchRadius;
extern f32 lbl_803E3038;
extern f32 lbl_803E3048;
extern void LandedArwing_UpdateRetreatChase(void);
extern void LandedArwing_UpdateBounceFade(void);
extern void LandedArwing_TriggerLaunchTarget(void);
extern void LandedArwing_ReturnZero(void);

#pragma fp_contract off
#pragma opt_common_subs off
void dll_D3_update(int* obj)
{
    int trans;
    int* state;
    LandedArwingState* extra;
    int* player;
    int hitCount;
    int rc;
    int hits;
    f32 vec[4];
    int aiStack_80[24];
#define searchRadius vec[0]
#define dx vec[1]
#define dy vec[2]
#define dz vec[3]

    trans = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    extra = (LandedArwingState*)((GroundBaddieState*)state)->control;
    player = Obj_GetPlayerObject();
    searchRadius = gStaffActionBoundsSearchRadius;

    if (extra->boundsObj == NULL)
    {
        extra->surfaceMode = 6;
        if (((u32)extra->flags92 >> 4 & 0xF) != 0u)
        {
            if ((extra->boundsObj = (void*)ObjList_FindNearestObjectByDefNo(obj, 0x4ad, &searchRadius)) != NULL)
            {
                (*(void (**)(int, int, int))(*(int**)*(int**)(*(int*)&extra->boundsObj + 0x68) + 0x20 / 4))(
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
        ((GameObject*)obj)->anim.localPosX = ((DllD3Placement*)trans)->posX;
        ((GameObject*)obj)->anim.localPosY = ((DllD3Placement*)trans)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((DllD3Placement*)trans)->posZ;
        (*gObjectTriggerInterface)->runSequence(((DllD3Placement*)trans)->unk2E, obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }

    rc = ((int (*)(int*, int*, int))((void**)*(int*)gBaddieControlInterface)[0x30 / 4])(obj, state, 0);
    if (rc == 0) return;

    if (((StaffBits*)&extra->flags92)->b1 == 0u)
    {
        if (ObjContact_AddCallback(obj, (int)player, fn_80167550) != 0)
        {
            ((StaffBits*)&extra->flags92)->b1 = 1;
        }
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, extra->animSpeed, timeDelta, NULL);

    if (((TreasureChestState*)state)->targetState != 1)
    {
        rc = ((int (*)(int*, int*, f32, int))((void**)*(int*)gBaddieControlInterface)[0x48 / 4])(
            obj, state,
            (f32)(u32)((TreasureChestState*)state)->aggroRange,
            0x8000);
        if (rc != 0u)
        {
            ((void (*)(int*, int*, int, int, int, int, int, int, int))((void**)*(int*)gBaddieControlInterface)[0x28 /
                4])(
                obj, state,
                (int)((char*)state + 0x35c),
                (int)((TreasureChestState*)state)->gameBitB,
                0, 0, 1, 0, -1);
            ((TreasureChestState*)state)->targetObj = rc;
            ((TreasureChestState*)state)->unk349 = 0;
            ((TreasureChestState*)state)->targetState = 1;
            ((TreasureChestState*)state)->unk405 = 2;
        }
    }

    if ((u32)((TreasureChestState*)state)->targetObj != 0 &&
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
        dx = ((GameObject*)(((TreasureChestState*)state)->targetObj))->anim.worldPosX -
            ((GameObject*)obj)->anim.worldPosX;
        dy = ((GameObject*)(((TreasureChestState*)state)->targetObj))->anim.worldPosY -
            ((GameObject*)obj)->anim.worldPosY;
        dz = ((GameObject*)(((TreasureChestState*)state)->targetObj))->anim.worldPosZ -
            ((GameObject*)obj)->anim.worldPosZ;
        ((TreasureChestState*)state)->targetDistance =
            sqrtf(dz * dz + (dx * dx + dy * dy));
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
            lbl_803202E8, lbl_80320360, 0, gStaffActionHitLightParams);
        if ((int)((TreasureChestState*)state)->hitPoints < hits)
        {
            (*(void (**)(int))(*(int**)*(int**)(*(int*)&((GameObject*)player)->childObjs[0] + 0x68) + 0x50 / 4))(
                *(int*)&((GameObject*)player)->childObjs[0]);
            *(f32*)((char*)gStaffActionHitLightParams + 0xc) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)gStaffActionHitLightParams + 0x10) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)gStaffActionHitLightParams + 0x14) = ((GameObject*)obj)->anim.localPosZ;
            objLightFn_8009a1dc(obj, lbl_803E3038, gStaffActionHitLightParams, 1, 0);
        }
    }

    ((void (*)(int*, int*, f32, int))((void**)*(int*)gBaddieControlInterface)[0x2c / 4])(
        obj, state, lbl_803E2FDC, -1);

    ((TreasureChestState*)state)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;

    ((void (*)(int*, int*, f32, f32, void**, void*))((void**)*(int*)gPlayerInterface)[8 / 4])(
        obj, state, timeDelta, timeDelta, gLandedArwingStateHandlers, &gLandedArwingDefaultStateHandler);

    *(int*)&((GameObject*)obj)->pendingParentObj = ((TreasureChestState*)state)->savedObjC0;

    if (((StaffBits*)&extra->flags92)->b0 == 0u &&
        extra->surfaceMode == 6)
    {
        hitCount = objBboxFn_800640cc(
            (int)((char*)obj + 0x80),
            &((GameObject*)obj)->anim.localPosX,
            lbl_803E3030, 0,
            aiStack_80, obj, -0x7c, -1, 0xff, 0);
        if (hitCount != 0 && *(s8*)((char*)aiStack_80 + 0x50) == 13)
        {
            ((StaffBits*)&extra->flags92)->b0 = 1;
            extra->scriptTimer = (u16)(randomGetRange(10, 0xf) * 0x3c);
        }
    }
}
#undef searchRadius
#undef dx
#undef dy
#undef dz
#pragma opt_common_subs reset
#pragma fp_contract on

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

    extra = (LandedArwingState*)((GroundBaddieState*)state)->control;
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
