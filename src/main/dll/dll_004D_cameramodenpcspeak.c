/*
 * DLL 0x004D (cameramodenpcspeak) - the dialogue/"NPC speak" camera mode.
 *
 * Lazily allocates a single CameraModeNpcSpeakState on first init and frees it
 * on free. init() seeds the anchor point from the init
 * params or, when none are given, from the focused NPC's position, then
 * picks a tuning preset from the mode id (0-8; mode 4 randomizes to 0-3)
 * that drives distance/height offsets, look-at scales and the starting
 * orbit angle. It chooses the shorter orbit direction toward the target and
 * flips it away from the NPC's facing where needed. update() places the
 * camera on that orbit each frame (mode 6 advances the orbit by a clamped
 * angular velocity), aims rotX/rotY at the look-at point, drives the blur
 * filter and converts the result back to local space. The orbit-position
 * solver is shared by init and update.
 */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/resource.h"
#include "main/game_object.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/mm.h"
#include "main/maketex_api.h"
#include "main/dll/CAM/cutCam.h"
#include "main/rcp_dolphin_api.h"
#include "main/object_transform.h"
#include "main/obj_query.h"
#include "main/frame_timing.h"
#include "main/dll/dll_004D_cameramodenpcspeak.h"

CameraModeNpcSpeakState* gCameraModeNpcSpeakState;
f32 gCameraModeNpcSpeakMode6AnchorLerpScale;

f32 gCameraModeNpcSpeakMode6TargetHeightOffset = 30.0f;
f32 gCameraModeNpcSpeakMode6LookAtHeightOffset = 30.0f;
f32 gCameraModeNpcSpeakMode6LookAtYScale = 0.2f;
f32 gCameraModeNpcSpeakMode6LookAtXZScale = 0.2f;
f32 gCameraModeNpcSpeakMode6DistanceOffset = 4.0f;
int gCameraModeNpcSpeakMode6OrbitAngleOffset = 10000;
f32 gCameraModeNpcSpeakMode3DistanceOffset = 2.0f;
f32 gCameraModeNpcSpeakMode3PitchScale = 0.09f;


void CameraModeNpcSpeak_solveOrbitPosition(GameObject* target, f32* outX, f32* outY, f32* outZ)
{
    CameraModeNpcSpeakState* state = gCameraModeNpcSpeakState;
    f32 dx;
    f32 dz;
    f32 dist;
    u16 angle;
    f32 cosVal;
    f32 sinVal;

    dx = target->anim.worldPosX - state->anchorX;
    dz = target->anim.worldPosZ - state->anchorZ;
    dist = sqrtf(dx * dx + dz * dz);
    angle = getAngle(dx, dz);

    {
        f32 scale = gCameraModeNpcSpeakState->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(3.1415927f * (f32)(s32)(angle + gCameraModeNpcSpeakState->orbitAngleOffset) /
                      32768.0f);
    sinVal = mathCosf(3.1415927f * (f32)(s32)(angle + gCameraModeNpcSpeakState->orbitAngleOffset) /
                      32768.0f);

    if (dist < gCameraModeNpcSpeakState->minDistance)
    {
        dist = gCameraModeNpcSpeakState->minDistance;
    }
    dist += gCameraModeNpcSpeakState->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + gCameraModeNpcSpeakState->targetHeightOffset) -
            0.03f * ((30.0f + target->anim.worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}

void CameraModeNpcSpeak_copyToCurrent(void)
{
}

void CameraModeNpcSpeak_free(void)
{
    mm_free(gCameraModeNpcSpeakState);
    gCameraModeNpcSpeakState = NULL;
    Rcp_DisableBlurFilter();
}

void CameraModeNpcSpeak_update(CameraObject* camera)
{
    CameraModeNpcSpeakState* speakState;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 ex, ez, ey;
    f32 dx, dy, dz;

    if (target == NULL)
    {
        return;
    }
    speakState = gCameraModeNpcSpeakState;
    if (speakState->mode == 6)
    {
        speakState->orbitAngleOffset =
            (s32)((f32)speakState->orbitAngleVelocity * timeDelta + speakState->orbitAngleOffset);
        if (gCameraModeNpcSpeakState->orbitAngleVelocity > 0 && gCameraModeNpcSpeakState->orbitAngleOffset > 0xd6d8)
        {
            gCameraModeNpcSpeakState->orbitAngleOffset = 0xd6d8;
        }
        else if (gCameraModeNpcSpeakState->orbitAngleVelocity < 0 && gCameraModeNpcSpeakState->orbitAngleOffset < -0xd6d8)
        {
            gCameraModeNpcSpeakState->orbitAngleOffset = -0xd6d8;
        }
        CameraModeNpcSpeak_solveOrbitPosition(target, &gCameraModeNpcSpeakState->cameraX,
                                              &gCameraModeNpcSpeakState->cameraY,
                                              &gCameraModeNpcSpeakState->cameraZ);
    }
    camera->anim.worldPosX = gCameraModeNpcSpeakState->cameraX;
    camera->anim.worldPosY = gCameraModeNpcSpeakState->cameraY;
    camera->anim.worldPosZ = gCameraModeNpcSpeakState->cameraZ;
    dx = target->anim.worldPosX - speakState->anchorX;
    dy = (target->anim.worldPosY + gCameraModeNpcSpeakState->lookAtHeightOffset) - speakState->anchorY;
    dz = target->anim.worldPosZ - speakState->anchorZ;
    dx *= gCameraModeNpcSpeakState->lookAtXZScale;
    dy *= gCameraModeNpcSpeakState->lookAtYScale;
    dz *= gCameraModeNpcSpeakState->lookAtXZScale;
    if (gCameraModeNpcSpeakState->mode == 3)
    {
        camera->anim.rotY =
            (s16)(s32)getAngle(gCameraModeNpcSpeakMode3PitchScale * dy, sqrtf(dx * dx + dz * dz));
    }
    dx += speakState->anchorX;
    dy += speakState->anchorY;
    dz += speakState->anchorZ;
    ex = camera->anim.worldPosX - dx;
    ey = camera->anim.worldPosY - dy;
    ez = camera->anim.worldPosZ - dz;
    camera->anim.rotX = (s16)(0x8000 - getAngle(ex, ez));
    if (gCameraModeNpcSpeakState->mode != 3)
    {
        camera->anim.rotY = (s16)(s32)getAngle(ey, sqrtf(ex * ex + ez * ez));
    }
    turnOnBlurFilter(speakState->anchorX, speakState->anchorY, speakState->anchorZ, 1, 0);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}


ResourceDescriptorCallbacks7 gCameraModeNpcSpeakDescriptor = {{0x00000000, 0x00000000, 0x00000000, 0x00060000},
        {(ResourceDescriptorCallback)CameraModeNpcSpeak_initialise, (ResourceDescriptorCallback)CameraModeNpcSpeak_release,
        0x00000000, (ResourceDescriptorCallback)CameraModeNpcSpeak_init, (ResourceDescriptorCallback)CameraModeNpcSpeak_update,
        (ResourceDescriptorCallback)CameraModeNpcSpeak_free, (ResourceDescriptorCallback)CameraModeNpcSpeak_copyToCurrent}};
void CameraModeNpcSpeak_init(CameraObject* camera, int unused, CameraModeNpcSpeakInitParams* params)
{
#define target ((GameObject*)camera->anim.targetObj)
    u16 yawA, yawB;
    int mode = 0;
    int spd;
    int d1, d2;
    GameObject* npc;
    f32 vc, vb, va;
    u8 traceWork[CAMCONTROL_TRACE_WORK_SIZE];

    if (gCameraModeNpcSpeakState == NULL)
    {
        gCameraModeNpcSpeakState = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }

    if (params != NULL)
    {
        gCameraModeNpcSpeakState->anchorX = params->anchorX;
        gCameraModeNpcSpeakState->anchorY = params->anchorY;
        gCameraModeNpcSpeakState->anchorZ = params->anchorZ;
        mode = params->mode;
    }
    else
    {
        GameObject* focus = getFocusedNpc();
        f32* fpos;
        if (focus == NULL)
        {
            gCameraModeNpcSpeakState->anchorX = 0.0f;
            gCameraModeNpcSpeakState->anchorY = 0.0f;
            gCameraModeNpcSpeakState->anchorZ = 0.0f;
        }
        fpos = (f32*)focus->anim.hitVolumeTransforms;
        if (fpos == NULL)
        {
            gCameraModeNpcSpeakState->anchorX = 0.0f;
            gCameraModeNpcSpeakState->anchorY = 0.0f;
            gCameraModeNpcSpeakState->anchorZ = 0.0f;
        }
        gCameraModeNpcSpeakState->anchorX = fpos[0];
        gCameraModeNpcSpeakState->anchorY = fpos[1];
        gCameraModeNpcSpeakState->anchorZ = fpos[2];
    }
    if (mode == 4)
    {
        mode = randomGetRange(0, 3);
    }
    {
        f32 a, b;
        gCameraModeNpcSpeakState->unk20 = 0;
        gCameraModeNpcSpeakState->mode = mode;
        gCameraModeNpcSpeakState->unk14 = 0.0f;
        a = 25.0f;
        gCameraModeNpcSpeakState->targetHeightOffset = a;
        gCameraModeNpcSpeakState->lookAtHeightOffset = 30.0f;
        gCameraModeNpcSpeakState->lookAtYScale = 0.9f;
        b = 0.5f;
        gCameraModeNpcSpeakState->anchorLerpScale = b;
        gCameraModeNpcSpeakState->lookAtXZScale = b;
        gCameraModeNpcSpeakState->minDistance = a;
    }
    gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode)
    {
    case 0:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        break;
    case 1:
        gCameraModeNpcSpeakState->distanceOffset = 5.0f;
        break;
    case 2:
        gCameraModeNpcSpeakState->distanceOffset = 40.0f;
        break;
    case 5:
        gCameraModeNpcSpeakState->distanceOffset = 80.0f;
        break;
    case 3:
        gCameraModeNpcSpeakState->distanceOffset = gCameraModeNpcSpeakMode3DistanceOffset;
        gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        gCameraModeNpcSpeakState->lookAtHeightOffset = 0.0f;
        break;
    case 6:
        gCameraModeNpcSpeakState->targetHeightOffset = gCameraModeNpcSpeakMode6TargetHeightOffset;
        gCameraModeNpcSpeakState->lookAtHeightOffset = gCameraModeNpcSpeakMode6LookAtHeightOffset;
        gCameraModeNpcSpeakState->anchorLerpScale = gCameraModeNpcSpeakMode6AnchorLerpScale;
        gCameraModeNpcSpeakState->lookAtYScale = gCameraModeNpcSpeakMode6LookAtYScale;
        gCameraModeNpcSpeakState->orbitAngleOffset = gCameraModeNpcSpeakMode6OrbitAngleOffset;
        gCameraModeNpcSpeakState->lookAtXZScale = gCameraModeNpcSpeakMode6LookAtXZScale;
        gCameraModeNpcSpeakState->distanceOffset = gCameraModeNpcSpeakMode6DistanceOffset;
        gCameraModeNpcSpeakState->orbitAngleVelocity = 0xb6;
        gCameraModeNpcSpeakState->minDistance = 0.0f;
        break;
    case 7:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        gCameraModeNpcSpeakState->targetHeightOffset = 35.0f;
        gCameraModeNpcSpeakState->anchorLerpScale = 0.1f;
        gCameraModeNpcSpeakState->lookAtXZScale = 0.3f;
        gCameraModeNpcSpeakState->lookAtYScale = 0.6f;
        gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        gCameraModeNpcSpeakState->distanceOffset = 15.0f;
        gCameraModeNpcSpeakState->lookAtHeightOffset = 10.0f;
        break;
    default:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        break;
    }

    yawA = (u16)getAngle(camera->anim.worldPosX - gCameraModeNpcSpeakState->anchorX,
                         camera->anim.worldPosZ - gCameraModeNpcSpeakState->anchorZ);
    yawB = (u16)getAngle(target->anim.worldPosX - gCameraModeNpcSpeakState->anchorX,
                         target->anim.worldPosZ - gCameraModeNpcSpeakState->anchorZ);
    {
        CameraModeNpcSpeakState* state = gCameraModeNpcSpeakState;
        spd = state->orbitAngleOffset;
        d1 = (yawB + spd) - yawA;
        if (d1 > 0x8000)
        {
            d1 -= 0xffff;
        }
        if (d1 < -0x8000)
        {
            d1 += 0xffff;
        }
        d2 = (yawB - spd) - yawA;
        if (d2 > 0x8000)
        {
            d2 -= 0xffff;
        }
        if (d2 < -0x8000)
        {
            d2 += 0xffff;
        }
        if (d1 < 0)
        {
            d1 = -d1;
        }
        if (d2 < 0)
        {
            d2 = -d2;
        }
        if (d2 < d1)
        {
            state->orbitAngleOffset = -spd;
            gCameraModeNpcSpeakState->orbitAngleVelocity = -0x80;
        }
    }

    if (mode != 6 && mode != 7 && (npc = getFocusedNpc()) != NULL)
    {
        GameObject* tgt = target;
        s16 sd;
        int dd;
        sd = (s16)(yawB - (u16)tgt->anim.rotX);
        if (sd > 0x8000)
        {
            sd = (s16)(sd - 0xffff);
        }
        if (sd < -0x8000)
        {
            sd = (s16)(sd + 0xffff);
        }
        dd = sd - (u16)(s16)Obj_GetYawDeltaToObject(tgt, npc, 0);
        if (dd > 0x8000)
        {
            dd -= 0xffff;
        }
        if (dd < -0x8000)
        {
            dd += 0xffff;
        }
        if ((dd > 0x1000 && gCameraModeNpcSpeakState->orbitAngleOffset > 0) ||
            (dd < -0x1000 && gCameraModeNpcSpeakState->orbitAngleOffset < 0))
        {
            gCameraModeNpcSpeakState->orbitAngleOffset = -gCameraModeNpcSpeakState->orbitAngleOffset;
        }
    }

    CameraModeNpcSpeak_solveOrbitPosition(target, &va, &vb, &vc);
    camcontrol_traceMove(&camera->anim.worldPosX, &va, &gCameraModeNpcSpeakState->cameraX, traceWork, 3, 1, 1,
                         4.0f);
}

#undef target

f32 lbl_80319DF8[4] = {-3.0f, -3.5f, -3.5f, -3.0f};
void CameraModeNpcSpeak_release(void)
{
}

void CameraModeNpcSpeak_initialise(void)
{
}
