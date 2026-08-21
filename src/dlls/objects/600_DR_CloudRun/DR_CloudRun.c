/*
 * DR_CloudRun (DLL 0x258) - the rideable CloudRunner creature on
 * Dinosaur Planet. A large baddie-derived state machine that the player
 * mounts and flies. mountState is the shared VehicleMountState the player
 * drives through VehicleInterface::setMountState; the eight state
 * handlers (gDRCloudRunnerStateHandlers[0..7]) drive idle, scripted-move,
 * flight, restart and hit responses, dispatched through the shared
 * baddie/player interface in DR_CloudRunner_updateFlightControl.
 *
 * Free-flight (stateHandler05) integrates velocity from stick input,
 * gravity and a banking model, clamps speed/pitch/roll against the
 * per-move parameter table at gDRCloudRunnerMoveParamTable, and follows the wind-curve
 * collision path set up in DR_CloudRunner_setupPath. The air meter and several map
 * game bits are managed across init/free/hitDetect.
 *
 * CloudRunnerState (its 'extra' block, 0xbc8 bytes) lives in
 * cloudrunner_state.h; the two structs below are this DLL's private
 * overlays for the placement record and for the few extra fields the
 * shared struct does not yet name.
 */
#include "main/audio/sfx_play_api.h"
#include "main/camera.h"
#include "main/dll/partfx_interface.h"
#include "main/debug.h"
#include "main/byte_flags.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objtype.h"
#include "main/obj_path.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "dlls/object_descriptor.h"
#include "main/object_render.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_api.h"
#include "game/objects/object_setup.h"
#include "main/pad.h"
#include "game/objects/object.h"
#include "main/objhits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/dll_0258_drcloudrunner.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "dolphin/pad.h"
#include "main/voxmaps.h"

void* gDRCloudRunnerStateHandlers[8];
void* gDRCloudRunnerDefaultStateHandler;
s16 gDRCloudRunnerSmoothedRotX;
int gDRCloudRunnerAirMeterBaseline;

const Vec3f gDRCloudRunnerVecTable[5] = {
    {0.0f, 0.0f, 15.0f},
    {0.0f, 0.0f, 30.0f},
    {0.0f, 0.35f, 0.0f},
    {0.0f, 1.0f, 0.0f},
    {0.0f, 0.0f, 1.0f},
};

const s16 gDRCloudRunnerGameBitIds[4] = { 0xBF0, 0xBF1, 0xBF2, 0xBF3 };

const int gDRCloudRunnerCurveIds[4] = {20, 21, 22, 23};

STATIC_ASSERT(sizeof(CloudRunnerState) == 0xbc8);
#define DRCLOUDRUNNER_PARTFX             0x66
#define DRCLOUDRUNNER_CHILD_OBJ_PROJECTILE 0x42a



void DR_CloudRunner_setupPath(GameObject* obj, CloudRunnerState* state, int mode)
{
    DRCloudRunnerMoveParams* base = &gDRCloudRunnerMoveParamTable;
    u8 stk[4] = { 0, 1, 1, 1 };
    u8* pathState = (u8*)&state->baddie + 4;
    u8 moveMode;
    pathState[0x25b] = 1;
    moveMode = mode;
    if (moveMode == 1)
    {
        (*gPathControlInterface)->init(pathState, 0, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 1, &base->pathCollisionA, &lbl_803DC774, 8);
        (*gPathControlInterface)->setup(pathState, 1, &base->pathPointsA, &lbl_803DC770, &stk);
    }
    else if (moveMode == 2)
    {
        (*gPathControlInterface)->init(pathState, 3, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, &base->pathCollisionB, &lbl_803DC77C, 8);
        (*gPathControlInterface)->setup(pathState, 1, &base->pathPointsB, &lbl_803DC778, &stk);
    }
    else if (moveMode == 0)
    {
        (*gPathControlInterface)->init(pathState, 3, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, &base->pathCollisionC, &lbl_803DC784, 8);
        (*gPathControlInterface)->setup(pathState, 1, &base->pathPointsC, &lbl_803DC780, &stk);
    }
    (*gPathControlInterface)->attachObject(obj, pathState);
}
void DR_CloudRunner_func23(GameObject* obj, int mode, int* out)
{
    struct gbids
    {
        s16 a[4];
    } bits;
    struct curveids
    {
        int a[4];
    } curve;
    MoveLibTarget target;
    CloudRunnerState* inner;
    Obj_GetPlayerObject();
    curve = *(struct curveids*)gDRCloudRunnerCurveIds;
    bits = *(struct gbids*)&gDRCloudRunnerGameBitIds;
    inner = obj->extra;
    switch (mode)
    {
    case 2:
        if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) || inner->flagsBC1.b80)
        {
            *out = obj->anim.rotX;
            gDRCloudRunnerSmoothedRotX = obj->anim.rotX;
            inner->flagsBC1.b80 = 0;
        }
        else
        {
            s16* p;
            s16 ang;
            int i;
            s16 diff;
            s16 step;
            ang = obj->anim.rotX;
            i = 0;
            p = bits.a;
            do
            {
                if (mainGetBit(*p) != 0)
                {
                    break;
                }
                p += 1;
                i += 1;
            } while (i < 4);
            if (i != 4 && dll_2E_getCurveActionTarget(curve.a[i], &target) != 0)
            {
                s16 tmp = getAngle(target.x - obj->anim.localPosX, target.z - obj->anim.localPosZ);
                ang = tmp + gDRCloudRunnerHeadingAngleOffset;
            }
            diff = ang - (u16)gDRCloudRunnerSmoothedRotX;
            if (diff > 0x8000)
            {
                diff = diff - 0xffff;
            }
            if (diff < -0x8000)
            {
                diff = diff + 0xffff;
            }
            step = diff / 16;
            if (step < -0x50)
            {
                step = -0x50;
            }
            else if (step > 0x50)
            {
                step = 0x50;
            }
            gDRCloudRunnerSmoothedRotX = gDRCloudRunnerSmoothedRotX + (s16)step;
            *out = gDRCloudRunnerSmoothedRotX;
        }
        break;
    case 3:
        if (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)
        {
            *out = 0;
        }
        else
        {
            *out = 1;
        }
        break;
    case 4:
        *out = 1;
        break;
    }
}

void DR_CloudRunner_fireProjectile(GameObject* obj)
{
    f32 dir[3];
    f32 diff[3];
    f32 pos[3];
    f32 gC[2];
    f32 gB[2];
    f32 tr[2];
    f32* pdiff = diff;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } s1;
    CloudRunnerState* inner = (obj)->extra;
    GameObject* newObj;
    ObjPlacement* setup;
    f32 dist;
        if (Obj_CanSetupObject() == 0)
    {
        return;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_11e);
    setup = Obj_AllocObjectSetup(0x24, DRCLOUDRUNNER_CHILD_OBJ_PROJECTILE);
    setup->color[2] = 0xff;
    setup->color[3] = 0xff;
    setup->color[0] = 2;
    setup->color[1] = 1;
    setup->posX = inner->spawnPosX;
    setup->posY = inner->spawnPosY;
    setup->posZ = inner->spawnPosZ;
    newObj = objSetupObject(setup, 5, -1, -1, NULL);
    if (newObj == NULL)
    {
        return;
    }
    s1.mat[1] = 0.0f;
    s1.mat[2] = 0.0f;
    s1.mat[3] = 0.0f;
    s1.mat[0] = 1.0f;
    s1.angles[0] = (obj)->anim.rotX;
    s1.angles[1] = (s16)(((obj)->anim.rotY - 0x190) >> 1);
    s1.angles[2] = 0;
    dir[0] = 0.0f;
    dir[1] = 0.0f;
    dir[2] = -16.0f;
    vecRotateZXY(s1.angles, dir);
    newObj->anim.velocityX = dir[0];
    newObj->anim.velocityY = dir[1];
    newObj->anim.velocityZ = dir[2];
    pos[0] = 300.0f * newObj->anim.velocityX;
    pos[1] = 300.0f * newObj->anim.velocityY;
    pos[2] = 300.0f * newObj->anim.velocityZ;
    pos[0] = newObj->anim.localPosX + pos[0];
    pos[1] = newObj->anim.localPosY + pos[1];
    pos[2] = newObj->anim.localPosZ + pos[2];
    voxmaps_worldToGrid((void*)&(obj)->anim.worldPosX, (s16*)gC);
    voxmaps_worldToGrid(pos, (s16*)gB);
    if (voxmaps_traceLine((VoxPos*)gC, (VoxPos*)gB, (VoxPos*)tr, NULL, 0) == 0)
    {
        voxmaps_gridToWorld(pos, (s16*)tr);
        diff[0] = pos[0] - newObj->anim.localPosX;
        diff[1] = pos[1] - newObj->anim.localPosY;
        diff[2] = pos[2] - newObj->anim.localPosZ;
        dist = sqrtf(pdiff[2] * pdiff[2] + (pdiff[0] * pdiff[0] + pdiff[1] * pdiff[1]));
    }
    else
    {
        dist = 200.0f;
    }
    newObj->userData1 = dist;
    newObj->userData2 = (int)obj;
    newObj->anim.rotZ = 0;
    newObj->anim.rotY = 0;
    newObj->anim.rotX = 0;
    (*gPartfxInterface)->spawnObject(newObj, DRCLOUDRUNNER_PARTFX, NULL, 2, -1, NULL);
}

#define DRCLOUDRUNNER_OBJGROUP           0xa
#define PLAYER_VEHICLE_OBJGROUP               0x26
#define DRCLOUDRUNNER_AIRMETER_BGTEXTURE 0x5de /* HUD air-meter background texture id */


#define CLOUDRUNNER_ONCLOUD_GAMEBIT 0xed7 /* set while mounted/on cloudrunner */

/* projectile the cloudrunner fires: velocity aimed from rotation, partfx trail */

int DR_CloudRunner_defaultStateHandler(void)
{
    return 0x0;
}

int DR_CloudRunner_stateHandler07(GameObject* obj)
{
    CloudRunnerState* inner = obj->extra;
    if (inner->airTimeRemaining == 0)
    {
        s32 a = obj->anim.alpha;
        a -= framesThisStep;
        obj->anim.alpha = a;
    }
    return 0;
}

int DR_CloudRunner_stateHandler06(GameObject* obj, CloudRunnerState* baddie)
{
    CloudRunnerState* inner = (obj)->extra;
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    baddie->baddie.flags0 |= 0x200000;
    if (baddie->baddie.moveJustStartedA != 0)
    {
        f32 dir[3];
        struct
        {
            s16 angles[4];
            f32 mat[4];
        } s1;
        GameObject* newObj;
        ObjPlacement* setup;
        inner->flagsBB6 &= ~8;
        hitState->flags = hitState->flags | 0x200;
        ObjAnim_SetCurrentMove(obj, 0xd, 0.0f, 0);
        baddie->baddie.moveSpeed = 0.011f;
        if (Obj_CanSetupObject() == 0)
        {
            return 0;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_11e);
        setup = Obj_AllocObjectSetup(0x18, DRCLOUDRUNNER_CHILD_OBJ_PROJECTILE);
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        setup->color[0] = 2;
        setup->color[1] = 1;
        setup->posX = inner->spawnPosX;
        setup->posY = inner->spawnPosY;
        setup->posZ = inner->spawnPosZ;
        newObj = objSetupObject(setup, 5, -1, -1, NULL);
        if (newObj != NULL)
        {
            s1.mat[1] = 0.0f;
            s1.mat[2] = 0.0f;
            s1.mat[3] = 0.0f;
            s1.mat[0] = 1.0f;
            s1.angles[0] = (obj)->anim.rotX;
            s1.angles[1] = (s16)(((obj)->anim.rotY - 0x190) >> 1);
            s1.angles[2] = 0;
            dir[0] = 0.0f;
            dir[1] = 0.0f;
            dir[2] = -16.0f;
            vecRotateZXY(s1.angles, dir);
            newObj->anim.velocityX = dir[0];
            newObj->anim.velocityY = dir[1];
            newObj->anim.velocityZ = dir[2];
            newObj->userData1 = 0xb4;
            newObj->userData2 = (int)obj;
            newObj->anim.rotZ = 0;
            newObj->anim.rotY = 0;
            newObj->anim.rotX = 0;
            (*gPartfxInterface)->spawnObject(newObj, DRCLOUDRUNNER_PARTFX, NULL, 2, -1, NULL);
        }
    }
    return 0;
}

int DR_CloudRunner_stateHandler05(GameObject* obj, CloudRunnerState* baddie, f32 f)
{
    Vec3f* vt = (Vec3f*)gDRCloudRunnerVecTable;
    DRCloudRunnerMoveParams* base = &gDRCloudRunnerMoveParamTable;
    u32 idx;
    int needMove = 0;
    CloudRunnerState* inner;
    int moveId;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } s1;
    Vec3f vecB;
    Vec3f vecC;
    Vec3f vecN;
    Vec3f vecD;
    Vec3f vecE;
    f32 speed;
    f32 accel;
    f32 grav;
    f32 mag;
    f32 adot;
    f32 animSpd;
    f32 spd;
    f32 dot;
    f32 dist;
    f32 t;
    f32* lim;
    vecB = vt[2];
    vecC = vt[3];
    vecD = vt[4];
    moveId = -1;
    inner = obj->extra;
    baddie->baddie.flags0 |= 0x200000;
    baddie->baddie.physicsActive = 0;
    if (baddie->baddie.moveDone != 0)
    {
        inner->flagsBC0.b80 = 0;
        inner->flagsBC0.b08 = 0;
        needMove = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (baddie->baddie.moveJustStartedA != 0)
    {
        if (!inner->flagsBC0.b20)
        {
            inner->flagsBC0.b20 = 1;
            DR_CloudRunner_setupPath(obj, baddie, inner->flagsBC0.b20);
        }
        ObjAnim_SetCurrentMove(obj, base->moveIds[4], 0.0f, 0);
        inner->pitchAngle = base->pitchAngles[4];
        inner->headingAngle = obj->anim.rotX;
        inner->rollAngle = obj->anim.rotZ;
        {
            f32 fz = 0.0f;
            baddie->baddie.animSpeedC = fz;
            baddie->baddie.animSpeedB = fz;
            baddie->baddie.animSpeedA = fz;
            obj->anim.velocityX = fz;
            obj->anim.velocityY = fz;
            obj->anim.velocityZ = fz;
        }
        needMove = 1;
        inner->flagsBC0.b80 = 1;
        inner->lastPosX = obj->anim.localPosX;
        inner->lastPosY = obj->anim.localPosY;
        inner->lastPosZ = obj->anim.localPosZ;
    }
    baddie->baddie.flags0 |= 0x1000000;
    if (baddie->baddie.inputMagnitude < 0.05f)
    {
        baddie->baddie.turnRateAbs = 0;
        baddie->baddie.turnRate = 0;
        {
            f32 fz = 0.0f;
            baddie->baddie.moveInputX = fz;
            baddie->baddie.moveInputZ = fz;
            baddie->baddie.inputMagnitude = fz;
        }
    }
    speed = obj->anim.currentMoveProgress;
    {
        s16* p;
        s16 curMove;
        for (idx = 0, p = base->moveIds, curMove = obj->anim.currentMove; curMove != *p && idx < 6;
             idx++)
        {
            p += 1;
        }
    }
    if (idx >= 6)
    {
        idx = 4;
    }
    mag = sqrtf(obj->anim.velocityX * obj->anim.velocityX +
                obj->anim.velocityZ * obj->anim.velocityZ);
    spd = (mag < 0.0f) ? 0.0f : ((mag > 4.7f) ? 4.7f : mag);
    obj->anim.velocityY =
        obj->anim.velocityY + (accel = ((grav = 0.02f) * spd) / 4.7f);
    obj->anim.velocityY = obj->anim.velocityY - grav;
    if (spd > 0.0f)
    {
        if ((int)idx >= 4)
        {
            s1.angles[2] = obj->anim.rotZ;
            s1.angles[1] = inner->pitchAngle - 0x4000;
            s1.angles[0] = obj->anim.rotX;
            s1.mat[1] = 0.0f;
            s1.mat[2] = 0.0f;
            s1.mat[3] = 0.0f;
            s1.mat[0] = 1.0f;
            vecD.z = -1.0f;
            vecRotateZXY(s1.angles, &vecC.x);
            vecRotateZXY(s1.angles, &vecD.x);
            vecC.x = vecC.x * accel;
            vecC.y = vecC.y * accel;
            vecC.z = vecC.z * accel;
            obj->anim.velocityX = obj->anim.velocityX + vecC.x;
            obj->anim.velocityZ = obj->anim.velocityZ + vecC.z;
        }
        else
        {
            s1.angles[2] = obj->anim.rotZ;
            s1.angles[1] = inner->pitchAngle;
            s1.angles[0] = obj->anim.rotX;
            s1.mat[1] = 0.0f;
            s1.mat[2] = 0.0f;
            s1.mat[3] = 0.0f;
            s1.mat[0] = 1.0f;
            vecRotateZXY(s1.angles, &vecD.x);
            vecN.x = -obj->anim.velocityX;
            vecN.y = -obj->anim.velocityY;
            vecN.z = -obj->anim.velocityZ;
            dot = vecD.z * vecN.z + (vecD.x * vecN.x + vecD.y * vecN.y);
            adot = dot >= 0.0f ? dot : -dot;
            Vec3_Normalize(&vecN.x);
            vecN.x = vecN.x * (0.001f * adot + 0.02f * ((0.35f * adot) / 4.7f));
            vecN.y = vecN.y * (0.001f * adot + 0.02f * ((0.35f * adot) / 4.7f));
            vecN.z = vecN.z * (0.001f * adot + 0.02f * ((0.35f * adot) / 4.7f));
            obj->anim.velocityX = obj->anim.velocityX + vecN.x;
            obj->anim.velocityY = obj->anim.velocityY + vecN.y;
            obj->anim.velocityZ = obj->anim.velocityZ + vecN.z;
        }
    }
    if (baddie->baddie.inputMagnitude > 0.05f)
    {
        s1.angles[2] = 0;
        s1.angles[1] = 0;
        s1.angles[0] = obj->anim.rotX;
        s1.mat[1] = 0.0f;
        s1.mat[2] = 0.0f;
        s1.mat[3] = 0.0f;
        s1.mat[0] = 1.0f;
        vecC.x =
            baddie->baddie.moveInputX / 64.0f * base->inputScaleX[(int)idx >> 1];
        vecC.y =
            -baddie->baddie.moveInputZ / 64.0f * base->inputScaleZ[(int)idx >> 1];
        vecC.z = 0.0f;
        vecRotateZXY(s1.angles, &vecC.x);
        obj->anim.velocityX = obj->anim.velocityX + vecC.x;
        obj->anim.velocityY = obj->anim.velocityY + vecC.y;
        obj->anim.velocityZ = obj->anim.velocityZ + vecC.z;
    }
    if (inner->flagsBC0.b80 & (obj->anim.currentMoveProgress < 0.5f))
    {
        s1.angles[2] = obj->anim.rotZ;
        s1.angles[1] = inner->pitchAngle;
        s1.angles[0] = obj->anim.rotX;
        s1.mat[1] = 0.0f;
        s1.mat[2] = 0.0f;
        s1.mat[3] = 0.0f;
        s1.mat[0] = 1.0f;
        vecRotateZXY(s1.angles, &vecB.x);
        obj->anim.velocityX = obj->anim.velocityX + vecB.x;
        obj->anim.velocityY = obj->anim.velocityY + vecB.y;
        obj->anim.velocityZ = obj->anim.velocityZ + vecB.z;
    }
    mag = sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                (obj->anim.velocityX * obj->anim.velocityX +
                 obj->anim.velocityY * obj->anim.velocityY));
    if (mag > *(lim = (f32*)((u8*)base + 0xa8) + ((int)idx >> 1)))
    {
        Vec3_Normalize(&obj->anim.velocityX);
        obj->anim.velocityX = obj->anim.velocityX * ((mag + *lim) / 2.0f);
        obj->anim.velocityY = obj->anim.velocityY * ((mag + *lim) / 2.0f);
        obj->anim.velocityZ = obj->anim.velocityZ * ((mag + *lim) / 2.0f);
    }
    else
    {
        if (mag < *(lim = (f32*)((u8*)base + 0xb4) + ((int)idx >> 1)))
        {
            Vec3_Normalize(&obj->anim.velocityX);
            obj->anim.velocityX =
                obj->anim.velocityX * ((mag + *lim) / 2.0f);
            obj->anim.velocityY = obj->anim.velocityY * ((mag + *lim) / 2.0f);
            obj->anim.velocityZ = obj->anim.velocityZ * ((mag + *lim) / 2.0f);
        }
    }
    if ((int)idx >= 4)
    {
        inner->headingAngle = inner->headingAngle - (int)baddie->baddie.moveInputX;
        inner->rollAngle = inner->rollAngle - ((int)baddie->baddie.moveInputX << 3);
        obj->anim.rotY =
            obj->anim.rotY - (int)baddie->baddie.moveInputZ * 3;
        inner->pitchAngle = inner->pitchAngle - (int)baddie->baddie.moveInputZ * 3;
    }
    else
    {
        inner->headingAngle = inner->headingAngle - ((int)baddie->baddie.moveInputX << 3);
        inner->rollAngle = inner->rollAngle - (int)baddie->baddie.moveInputX;
        obj->anim.rotY =
            obj->anim.rotY - (int)baddie->baddie.moveInputZ * 6;
        inner->pitchAngle = inner->pitchAngle - ((int)baddie->baddie.moveInputZ << 2);
    }
    if ((int)idx >= 4)
    {
        s16 ang;
        s16 diff;
        ang = (s16)(getAngle(obj->anim.velocityX, obj->anim.velocityZ) + 0x8000);
        diff = ang - (u16)inner->headingAngle;
        if (diff > 0x8000)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff = diff + 0xffff;
        }
        inner->headingAngle += diff / 64;
        inner->rollAngle += diff / 128;
    }
    {
        s16 lim2;
        if (inner->rollAngle > (lim2 = *(s16*)((char*)&gDRCloudRunnerRollAngleLimits + (idx & 0xfffffffe))))
        {
            inner->rollAngle = lim2;
        }
        else
        {
            int neg = -lim2;
            if (inner->rollAngle < neg)
            {
                inner->rollAngle = neg;
            }
        }
    }
    if (inner->pitchAngle > 0x4000)
    {
        inner->pitchAngle = 0x4000;
    }
    else if (inner->pitchAngle < -0x4000)
    {
        inner->pitchAngle = -0x4000;
    }
    obj->anim.rotX = inner->headingAngle;
    obj->anim.rotZ = inner->rollAngle;
    mag = sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                (obj->anim.velocityX * obj->anim.velocityX +
                 obj->anim.velocityY * obj->anim.velocityY));
    if (inner->flagsBC0.b80 == 0 && (baddie->baddie.pressedButtons & 0x200))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sliftloop11);
        inner->flagsBC0.b80 = 1;
        speed = 0.0f;
        needMove = 1;
    }
    if (baddie->baddie.flags0 & 0x400000)
    {
        vecE.x = obj->anim.previousLocalPosX - inner->lastPosX;
        vecE.y = obj->anim.previousLocalPosY - inner->lastPosY;
        vecE.z = obj->anim.previousLocalPosZ - inner->lastPosZ;
        dist = sqrtf(vecE.z * vecE.z + (vecE.x * vecE.x + vecE.y * vecE.y));
        t = (dist < 0.0f) ? 0.0f : ((dist > 30.0f) ? 30.0f : dist);
        Vec3_Normalize(&vecE.x);
        {
            f32 scale = (t / 30.0f) * (0.3f + (mag / 4.7f) * (mag / 4.7f));
            vecE.x = vecE.x * (scale / f);
            vecE.y = vecE.y * (scale / f);
            vecE.z = vecE.z * (scale / f);
        }
        if (vecE.y < 0.0f)
        {
            vecE.y = 0.0f;
        }
        vecE.y *= 0.2f;
        t = (vecE.y >= 0.0f) ? vecE.y : -vecE.y;
        t = (5.0f - t) / 5.0f;
        if (t < 0.0f)
        {
            t = 0.0f;
        }
        vecE.x = vecE.x * t;
        vecE.y = vecE.y * t;
        vecE.z = vecE.z * t;
        obj->anim.velocityX = vecE.x + obj->anim.velocityX;
        obj->anim.velocityY = vecE.y + obj->anim.velocityY;
        obj->anim.velocityZ = vecE.z + obj->anim.velocityZ;
        obj->anim.localPosX = inner->lastPosX;
        obj->anim.localPosY = inner->lastPosY;
        obj->anim.localPosZ = inner->lastPosZ;
        objMove(obj, obj->anim.velocityX, obj->anim.velocityY,
                obj->anim.velocityZ);
        if ((baddie->baddie.surfaceFlags & 0x10) && (int)(idx & 0xfe) == 0)
        {
            obj->anim.velocityY = -0.1f;
            return 3;
        }
        inner->lastPosX = obj->anim.localPosX;
        inner->lastPosY = obj->anim.localPosY;
        inner->lastPosZ = obj->anim.localPosZ;
    }
    else
    {
        objMove(obj, obj->anim.velocityX, obj->anim.velocityY,
                obj->anim.velocityZ);
    }
    if (inner->flagsBC0.b08 == 0 && (baddie->baddie.pressedButtons & 0x100))
    {
        buttonDisable(0, PAD_BUTTON_A);
        moveId = 0x20d;
        animSpd = 0.025f;
        inner->flagsBC0.b08 = 1;
        needMove = 1;
        speed = 0.0f;
    }
    if (needMove != 0)
    {
        if (moveId == -1)
        {
            int masked;
            int lift;
            ObjAnim_SetCurrentMove(
                obj,
                base->moveIds[(masked = idx & 0xfe) + (lift = inner->flagsBC0.b80)],
                speed, 0);
            baddie->baddie.moveSpeed = base->moveSpeeds[masked >> 1];
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, moveId, speed, 0);
            baddie->baddie.moveSpeed = animSpd;
        }
    }
    return 0;
}

int DR_CloudRunner_stateHandler04(GameObject* obj, CloudRunnerState* baddie)
{
    CloudRunnerState* inner = (obj)->extra;
    baddie->baddie.flags0 |= 0x1204000;
    baddie->baddie.physicsActive = 0;
    if (baddie->baddie.moveJustStartedA != 0)
    {
        f32 fz = 0.0f;
        CloudRunnerState* inner2;
        DRCloudRunnerPlacement* placement;
        baddie->baddie.animSpeedC = fz;
        baddie->baddie.animSpeedB = fz;
        baddie->baddie.animSpeedA = fz;
        (obj)->anim.velocityX = fz;
        (obj)->anim.velocityY = fz;
        (obj)->anim.velocityZ = fz;
        inner2 = (obj)->extra;
        placement = (DRCloudRunnerPlacement*)(obj)->anim.placementData;
        inner2->flagsBC0.b02 = 1;
        (*gGameUIInterface)
            ->initAirMeter(placement->airMeterCapacity, DRCLOUDRUNNER_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->runAirMeter(inner2->airTimeRemaining);
        baddie->baddie.controlTimer = 0;
        baddie->baddie.moveSpeed = 0.005f;
        baddie->baddie.velSmoothTime = 12.0f;
        ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
        inner->flagsBC0.b01 = 1;
    }
    {
        f32 fz = 0.0f;
        baddie->baddie.animSpeedC = fz;
        baddie->baddie.animSpeedB = fz;
        baddie->baddie.animSpeedA = fz;
        (obj)->anim.velocityX = fz;
        (obj)->anim.velocityY = fz;
        (obj)->anim.velocityZ = fz;
    }
    (obj)->anim.localPosX = inner->curveWalker.posX;
    (obj)->anim.localPosY = inner->curveWalker.posY;
    (obj)->anim.localPosZ = inner->curveWalker.posZ;
    {
        int a0;
        int a1;
        a0 = getAngle(-inner->curveWalker.tangentX, -inner->curveWalker.tangentZ) & 0xffff;
        a1 = getAngle(inner->curveWalker.tangentY,
                      sqrtf(inner->curveWalker.tangentX * inner->curveWalker.tangentX + inner->curveWalker.tangentZ * inner->curveWalker.tangentZ)) &
             0xffff;
        a0 -= (u16)(obj)->anim.rotX;
        if (a0 > 0x8000)
        {
            a0 = a0 - 0xffff;
        }
        if (a0 < -0x8000)
        {
            a0 = a0 + 0xffff;
        }
        (obj)->anim.rotX = (f32)(s32)(obj)->anim.rotX + interpolate((f32)(s32)a0, 0.03125f, timeDelta);
        a1 -= (u16)(obj)->anim.rotY;
        if (a1 > 0x8000)
        {
            a1 = a1 - 0xffff;
        }
        if (a1 < -0x8000)
        {
            a1 = a1 + 0xffff;
        }
        (obj)->anim.rotY = (f32)(s32)(obj)->anim.rotY + interpolate((f32)(s32)a1, 0.03125f, timeDelta);
        (obj)->anim.rotZ = (s16)(a0 >> 5);
    }
    {
        int v = (obj)->anim.rotZ;
        if (v < -0x1000)
        {
            v = -0x1000;
        }
        else if (v > 0x1000)
        {
            v = 0x1000;
        }
        (obj)->anim.rotZ = v;
    }
    return 0;
}

int DR_CloudRunner_stateHandler03(GameObject* obj, CloudRunnerState* baddie)
{
    CloudRunnerState* inner = (obj)->extra;
    if (baddie->baddie.moveJustStartedA != 0)
    {
        inner->flagsBC0.b10 = 0;
        (obj)->anim.velocityY = 0.0f;
        if (inner->flagsBC0.b20)
        {
            inner->flagsBC0.b20 = 0;
            DR_CloudRunner_setupPath(obj, baddie, inner->flagsBC0.b20);
        }
    }
    switch ((obj)->anim.currentMove)
    {
    case 0x203:
        if (inner->airTimeRemaining != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x20c, 0.0f, 0);
            baddie->baddie.moveSpeed = 0.01f;
        }
        break;
    case 0x20c:
        if (baddie->baddie.moveDone != 0)
        {
            inner->moveLib.modeBits &= ~2;
            return 3;
        }
        break;
    default:
    {
        f32 fz;
        ObjAnim_SetCurrentMove(obj, 0x203, 0.0f, 0);
        inner->moveLib.modeBits |= 2;
        fz = 0.0f;
        baddie->baddie.animSpeedC = fz;
        baddie->baddie.animSpeedB = fz;
        baddie->baddie.animSpeedA = fz;
        (obj)->anim.velocityX = fz;
        (obj)->anim.velocityY = fz;
        (obj)->anim.velocityZ = fz;
        baddie->baddie.moveSpeed = 0.01f;
        break;
    }
    }
    return 0;
}

int DR_CloudRunner_stateHandler02(GameObject* obj, CloudRunnerState* baddie)
{
    CloudRunnerState* inner = (obj)->extra;
    baddie->baddie.flags0 |= 0x200000;
    if (baddie->baddie.moveJustStartedA != 0)
    {
        f32 fz = 0.0f;
        baddie->baddie.animSpeedC = fz;
        baddie->baddie.animSpeedB = fz;
        baddie->baddie.animSpeedA = fz;
        (obj)->anim.velocityX = fz;
        (obj)->anim.velocityY = fz;
        (obj)->anim.velocityZ = fz;
        baddie->baddie.controlTimer = 0;
        baddie->baddie.moveSpeed = 0.005f;
        baddie->baddie.velSmoothTime = 12.0f;
        if ((obj)->anim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, fz, 0);
        }
        if (inner->flagsBC0.b20)
        {
            inner->flagsBC0.b20 = 0;
            baddie->baddie.physicsActive = 0;
        }
    }
    if (baddie->baddie.inputMagnitude < 0.05f)
    {
        baddie->baddie.turnRateAbs = 0;
        baddie->baddie.turnRate = 0;
        baddie->baddie.inputMagnitude = 0.0f;
    }
    return 0;
}

int DR_CloudRunner_stateHandler01(GameObject* obj, CloudRunnerState* baddie)
{
    CloudRunnerState* inner;
    DRCloudRunnerPlacement* placement = (DRCloudRunnerPlacement*)(obj)->anim.placementData;
    baddie->baddie.flags0 |= 0x200000;
    if (baddie->baddie.moveJustStartedA != 0)
    {
        f32 fz;
        ObjHits_DisableObject(obj);
        baddie->baddie.physicsActive = 0;
        baddie->baddie.moveSpeed = 0.01f;
        fz = 0.0f;
        baddie->baddie.animSpeedC = fz;
        baddie->baddie.animSpeedB = fz;
        baddie->baddie.animSpeedA = fz;
        (obj)->anim.velocityX = fz;
        (obj)->anim.velocityY = fz;
        (obj)->anim.velocityZ = fz;
        return 0;
    }
    inner = (obj)->extra;
    Vec_distance(&(obj)->anim.worldPosX, &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX);
    if (RandomTimer_UpdateRangeTrigger(&inner->randomTimerB54, 12.0f, 18.0f))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_lfoot_taunt);
    }
    if (mainGetBit(placement->enableGameBit) != 0)
    {
        (obj)->userData1 = 0;
        ObjHits_EnableObject(obj);
        ObjHits_SyncObjectPositionIfDirty(obj);
        inner->flagsBC0.b10 = inner->airTimeRemaining > 0;
        (obj)->anim.rotX = gDRCloudRunnerDefaultRotX;
        return 3;
    }
    return 0;
}

int DR_CloudRunner_stateHandler00(GameObject* obj)
{
    CloudRunnerState* inner = (obj)->extra;
    switch (inner->spawnVariant)
    {
    case 0:
        return 2;
    default:
        break;
    }
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    inner->flagsBC0.b10 = inner->airTimeRemaining > 0;
    return 3;
}
int DR_CloudRunner_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    CloudRunnerState* inner = obj->extra;
    int local = 1;
    int i;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((int)animUpdate->eventIds[i])
        {
        case 1:
            (*gRomCurveInterface)->initCurve(&inner->curveWalker, (void*)obj, 500.0f, &local, 0xf);
            break;
        default:
            break;
        }
    }
    inner->flagsBC1.b80 = 1;
    return 0;
}

void DR_CloudRunner_handleRiderScale(GameObject* obj)
{
    objSetModelMatrixOverride((f32*)ObjPath_GetPointModelMtx(obj, 2));
}

void DR_CloudRunner_func21(void)
{
}

int DR_CloudRunner_getRacePosition(void)
{
    return 0x0;
}

f32 DR_CloudRunner_func19(int obj, f32* out)
{
    *out = 5.0f;
    return 0.0f;
}

void DR_CloudRunner_getPlayerAnim(int obj, f32* a, int* b)
{
    *a = 0.0f;
    *b = 0;
}

void DR_CloudRunner_setMountState(GameObject* obj, int mountState)
{
    CloudRunnerState* inner = obj->extra;
    inner->mountState = mountState;
    if (mountState == VEHICLE_Mounting)
    {
        s16 seqIndex;
        inner->eyeAnimState.lookAtActive = 0;
        seqIndex = obj->seqIndex;
        if (seqIndex != -1)
        {
            (*gObjectTriggerInterface)->endSequence(seqIndex);
        }
    }
    else
    {
        inner->eyeAnimState.lookAtActive = 1;
    }
    if (mountState == VEHICLE_Mounted)
    {
        mainSetBits(CLOUDRUNNER_ONCLOUD_GAMEBIT, 1);
    }
    else
    {
        mainSetBits(CLOUDRUNNER_ONCLOUD_GAMEBIT, 0);
    }
}

int DR_CloudRunner_getMountState(void)
{
    return 0x0;
}

void DR_CloudRunner_getCameraPosition(GameObject* obj, f32* a, f32* b, f32* c)
{
    MatrixTransform v;
    f32 matrix[16];
    GameObject* src = Obj_GetPlayerObject();
    if (src == NULL)
    {
        src = obj;
    }
    v.x = src->anim.localPosX;
    v.y = src->anim.localPosY;
    v.z = src->anim.localPosZ;
    v.rotX = src->anim.rotX;
    v.rotY = src->anim.rotY;
    v.rotZ = src->anim.rotZ;
    v.scale = 1.0f;
    setMatrixFromObjectPos(matrix, &v);
    Matrix_TransformPoint(matrix, 0.0f, lbl_803DC78C, lbl_803DC790, a, b, c);
}

int DR_CloudRunner_getDismountSide(GameObject* obj)
{
    CloudRunnerState* inner = obj->extra;
    if (inner->dismountSide != 0)
    {
        return 2;
    }
    return 1;
}

int DR_CloudRunner_canDismount(void)
{
    return 0x0;
}

void DR_CloudRunner_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z)
{
    ObjPath_GetPointWorldPosition(obj, 2, x, y, z, 0);
}


int DR_CloudRunner_getMountSide(GameObject* obj)
{
    CloudRunnerState* inner = obj->extra;
    if (inner->mountSide != 0)
    {
        return 1;
    }
    return 2;
}

int DR_CloudRunner_canMount(void)
{
    return 0x0;
}

int DR_CloudRunner_getExtraSize(void)
{
    return sizeof(CloudRunnerState);
}

int DR_CloudRunner_getObjectTypeId(void)
{
    return 0x43;
}

void DR_CloudRunner_free(GameObject* obj)
{
    CloudRunnerState* inner = (obj)->extra;
    mainSetBits(0x7aa, inner->airTimeRemaining);
    objFreeObjectType(obj, DRCLOUDRUNNER_OBJGROUP);
    objFreeObjectType(obj, PLAYER_VEHICLE_OBJGROUP);
    (*gGameUIInterface)->airMeterShutdown();
}

void DR_CloudRunner_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    CloudRunnerState* inner = (obj)->extra;
    if ((obj)->userData1 == 0)
    {
        if (vis == -1)
        {
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            ObjPath_GetPointWorldPosition(obj, 3, &inner->spawnPosX, &inner->spawnPosY, &inner->spawnPosZ, 0);
        }
        if (inner->mountState != VEHICLE_Mounted && vis != 0)
        {
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            dll_2E_setTargetFromPathPoint(obj, &inner->moveLib, 0);
        }
    }
}

void DR_CloudRunner_hitDetect(GameObject* obj)
{
    CloudRunnerState* inner = (obj)->extra;
    int hitResult;
    GameObject* hits[4];
    s16 diff;
    if (inner->airTimeRemaining != 0 && (obj)->anim.currentMove != 0xf &&
        (hitResult = ObjHits_GetPriorityHit(obj, hits, 0, 0)) != 0 && hitResult != 0xf &&
        inner->mountState == VEHICLE_Mounted)
    {
        diff = (obj)->anim.rotX - (u16)hits[0]->anim.rotX;
        if (diff > 0x8000)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        if (diff > 0x4000 || diff < -0x4000)
        {
            inner->flagsBC0.b40 = 0;
        }
        else
        {
            inner->flagsBC0.b40 = 1;
        }
        inner->airTimeRemaining -= 1;
        if (inner->airTimeRemaining <= 0)
        {
            (*gGameUIInterface)->airMeterShutdown();
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
            inner->airTimeRemaining = 1;
            (*gPlayerInterface)->setState(obj, inner, 7);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_gscsc);
    }
}

void DR_CloudRunner_updateFlightControl(GameObject* obj, f32 f, int triggerFrame)
{
    CloudRunnerState* inner;
    int flag;
    Camera* slot;
    if (triggerFrame != -1)
    {
        flag = (((framesThisStep - 1) - triggerFrame) == 0);
    }
    else
    {
        flag = 1;
    }
    slot = Camera_GetCurrent();
    inner = (obj)->extra;
    inner->baddie.hitPoints = 0;
    inner->baddie.flags0 &= ~0x8000;
    inner->baddie.flags0 |= 0x200000;
    if (inner->mountState == VEHICLE_Mounted)
    {
        inner->baddie.moveInputX = (f32)padGetStickX(0);
        inner->baddie.moveInputZ = (f32)padGetStickY(0);
        inner->baddie.pressedButtons = getButtonsJustPressed(0);
        inner->baddie.heldButtons = getButtonsHeld(0);
        inner->baddie.cameraYaw = slot->yaw;
        if (inner->flagsBC0.b01 != 0)
        {
            Obj_UpdateRomCurveFollowVelocity(obj, &inner->curveWalker, inner->pathFollowSpeed,
                                             200.0f, 10.0f, 1);
        }
    }
    else
    {
        f32 v = 0.0f;
        inner->baddie.moveInputX = v;
        inner->baddie.moveInputZ = v;
        inner->baddie.pressedButtons = 0;
        inner->baddie.heldButtons = 0;
        inner->baddie.cameraYaw = 0;
    }
    inner->baddie.flags0 |= 0x400000;
    if (flag != 0)
    {
        inner->baddie.flags0 &= ~0x400000;
    }
    (*gPlayerInterface)->update(obj, inner, f, timeDelta, gDRCloudRunnerStateHandlers,
                                &gDRCloudRunnerDefaultStateHandler);
    if ((inner->baddie.eventFlags & 1) != 0)
    {
        DR_CloudRunner_fireProjectile(obj);
    }
    if (inner->flagsBC0.b02 != 0)
    {
        (*gGameUIInterface)->runAirMeter(inner->airTimeRemaining - gDRCloudRunnerAirMeterBaseline);
    }
}

void DR_CloudRunner_update(GameObject* obj)
{
    CloudRunnerState* inner;
    Obj_GetPlayerObject();
    inner = (obj)->extra;
    inner->unkBAE = 5;
    logPrintf(sOnCloudFormat, mainGetBit(CLOUDRUNNER_ONCLOUD_GAMEBIT));
    (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (inner->mountState == VEHICLE_Mounted)
    {
        (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        DR_CloudRunner_updateFlightControl(obj, timeDelta, -1);
        (&obj->anim)->modelInstance->flags |= 0x200000LL;
    }
    else
    {
        inner->baddie.physicsActive = 0;
        DR_CloudRunner_updateFlightControl(obj, timeDelta, -1);
        (&obj->anim)->modelInstance->flags &= ~0x200000LL;
    }
    if (inner->cooldownTimer != 0)
    {
        s8 v = inner->cooldownTimer - framesThisStep;
        inner->cooldownTimer = v;
        if (v < 0)
        {
            inner->cooldownTimer = 0;
        }
    }
    if (inner->mountState == VEHICLE_Mounted)
    {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        inner->moveLib.modeBits |= 1;
    }
    else
    {
        inner->moveLib.modeBits &= ~1;
    }
    dll_2E_updateLookAt(obj, &inner->moveLib);
    objSoundUpdateMouth(obj, &inner->modelSoundState);
    characterHeadLookCalm(obj, (s16*)&inner->eyeAnimState, 0.0f);
    characterDoEyeAnims(obj, &inner->eyeAnimState);
    if ((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED)
    {
        if (inner->mountState == VEHICLE_NoRider)
        {
            if (inner->flagsBC0.b10)
            {
                f32 vec[3];
                buttonDisable(0, PAD_BUTTON_A);
                if ((*gMapEventInterface)->getRestartGameNotCleared() == 0)
                {
                    vec[0] = -17427.0f;
                    vec[1] = -1763.0f;
                    vec[2] = 8864.0f;
                    (*gMapEventInterface)->restartPoint(vec, 0, 0, 0);
                }
                (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
                inner->unkB04 = 0;
                inner->flagsBB6 |= 4;
                inner->moveLib.modeBits |= 1;
                (*gPlayerInterface)->setState(obj, inner, 4);
            }
            else
            {
                buttonDisable(0, PAD_BUTTON_A);
                {
                    s8 t = inner->sequenceIndex;
                    if (t != -1)
                    {
                        (*gObjectTriggerInterface)->runSequence(t, (void*)obj, -1);
                    }
                }
            }
        }
    }
}

void DR_CloudRunner_init(GameObject* obj, DRCloudRunnerPlacement* def)
{
    MoveLibTarget target;
    CloudRunnerState* inner;
    int savedSlot;
    (obj)->anim.rotX = (s16)(def->spawnRot << 8);
    (obj)->animEventCallback = DR_CloudRunner_SeqFn;
    objAddObjectType(obj, DRCLOUDRUNNER_OBJGROUP);
    inner = obj->extra;
    inner->spawnVariant = def->spawnVariant;
    inner->unkBAE = 5;
    inner->airTimeRemaining = def->airMeterCapacity;
    inner->sequenceIndex = -1;
    inner->pathFollowSpeed = (f32)def->pathSpeedTenths / 10.0f;
    if ((obj)->anim.modelState != NULL)
    {
        (obj)->anim.modelState->flags |= 0xa10;
    }
    savedSlot = mainGetBit(0x7a9);
    if (savedSlot != 0)
    {
        dll_2E_getCurveActionTarget(savedSlot + 0x13, &target);
        (obj)->anim.localPosX = target.x;
        (obj)->anim.localPosY = target.y;
        (obj)->anim.localPosZ = target.z;
        (obj)->anim.rotX = target.angle;
    }
    (*gPlayerInterface)->init(obj, (void*)inner, 8, 1);
    inner->baddie.gravity = 0.17f;
    DR_CloudRunner_setupPath(obj, (CloudRunnerState*)inner, inner->flagsBC0.b20);
    dll_2E_initState(obj, &inner->moveLib, -0x11c7, 0x1555, 1);
    dll_2E_setReattackDelay(&inner->moveLib, 0x12c, 0x78);
    objAddObjectType(obj, PLAYER_VEHICLE_OBJGROUP);
    inner->flagsBC0.b01 = 0;
}

void DR_CloudRunner_release(void)
{
}

void DR_CloudRunner_initialise(void)
{
    gDRCloudRunnerStateHandlers[0] = DR_CloudRunner_stateHandler00;
    gDRCloudRunnerStateHandlers[1] = DR_CloudRunner_stateHandler01;
    gDRCloudRunnerStateHandlers[2] = DR_CloudRunner_stateHandler02;
    gDRCloudRunnerStateHandlers[3] = DR_CloudRunner_stateHandler03;
    gDRCloudRunnerStateHandlers[4] = DR_CloudRunner_stateHandler04;
    gDRCloudRunnerStateHandlers[5] = DR_CloudRunner_stateHandler05;
    gDRCloudRunnerStateHandlers[6] = DR_CloudRunner_stateHandler06;
    gDRCloudRunnerStateHandlers[7] = DR_CloudRunner_stateHandler07;
    gDRCloudRunnerDefaultStateHandler = DR_CloudRunner_defaultStateHandler;
}

DRCloudRunnerMoveParams gDRCloudRunnerMoveParamTable = {
    { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 },
    { 0.0f, 0.0f, 0.0f },
    { 0.0f, 0.0f, 0.0f },
    { 0.0f, 0.0f, 0.0f },
    { 0.0f, 0.0f, 0.0f },
    { 0.0f, 0.0f, 0.0f },
    { 0.0f, 0.0f, 20.0f },
    { 0.0f, 0.0f, -20.0f },
    { 0x117, 0x11C, 0x118, 0x11B, 0x116, 0x11E },
    { 9102, -1820, 910, -12743, -2730, -18204 },
    { 0.0f, 1.53f, 1.53f, 2.54f, 2.4f, 4.7f },
    { 0.02f, 0.03f, 0.06f },
    { 0.02f, 0.03f, 0.1f },
    { 1.5f, 4.2f, 4.6f },
    { 0.0f, 0.7f, 1.0f },
    { 0.02f, 0.02f, 0.04f, 0.01f },
};

ObjectDescriptor24 gDR_CloudRunnerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)DR_CloudRunner_initialise,
    (ObjectDescriptorCallback)DR_CloudRunner_release,
    0,
    (ObjectDescriptorCallback)DR_CloudRunner_init,
    (ObjectDescriptorCallback)DR_CloudRunner_update,
    (ObjectDescriptorCallback)DR_CloudRunner_hitDetect,
    (ObjectDescriptorCallback)DR_CloudRunner_render,
    (ObjectDescriptorCallback)DR_CloudRunner_free,
    (ObjectDescriptorCallback)DR_CloudRunner_getObjectTypeId,
    DR_CloudRunner_getExtraSize,
    (ObjectDescriptorCallback)DR_CloudRunner_canMount,
    (ObjectDescriptorCallback)DR_CloudRunner_getMountSide,
    (ObjectDescriptorCallback)DR_CloudRunner_getRiderPosition,
    (ObjectDescriptorCallback)DR_CloudRunner_canDismount,
    (ObjectDescriptorCallback)DR_CloudRunner_getDismountSide,
    (ObjectDescriptorCallback)DR_CloudRunner_getCameraPosition,
    (ObjectDescriptorCallback)DR_CloudRunner_getMountState,
    (ObjectDescriptorCallback)DR_CloudRunner_setMountState,
    (ObjectDescriptorCallback)DR_CloudRunner_getPlayerAnim,
    (ObjectDescriptorCallback)DR_CloudRunner_func19,
    (ObjectDescriptorCallback)DR_CloudRunner_getRacePosition,
    (ObjectDescriptorCallback)DR_CloudRunner_func21,
    (ObjectDescriptorCallback)DR_CloudRunner_handleRiderScale,
    (ObjectDescriptorCallback)DR_CloudRunner_func23,
};

char sOnCloudFormat[] = "ON CLOUD=%d\n";
