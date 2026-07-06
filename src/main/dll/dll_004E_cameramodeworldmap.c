/*
 * DLL 0x004E - camera mode: world map.
 *
 * The world-map camera follows a focus object across the planet map. Its
 * state (CameraModeWorldMapState, allocated lazily in _init via gCamWorldMapState)
 * tracks the orbit distance/velocity, a settle counter and a focus-blend
 * timer. _copyToCurrent feeds the mode byte and focus-object id from the
 * map UI; _update runs one of two cameras keyed on that mode:
 *   mode 0: free overview - C-stick yaws/pitches the orbit, L/R (button bits
 *           4/8) zoom, distance eased between gCamWorldMapDistanceMin..gCamWorldMapDistanceMax, and
 *           a focus blend slews the camera toward the focus object.
 *   mode 1: locked path camera aimed from a fixed pitch, also driving the
 *           map marker/reticle object (0x43077) and widescreen offset.
 * Both modes orbit around the map reference object (0x42fff): mode 0 blends
 * the focus toward it, mode 1 aims the path camera from it.
 * Each frame _update also points the compass marker (0x431dc) and fades the
 * highlight object (0x4325b) by view angle. A 0xC-class screen transition
 * gates entry to each mode.
 */
#include "main/mm.h"
#include "main/dll/CAM/camworldmap_state.h"
#include "main/game_object.h"
#include "main/screen_transition.h"
#include "main/pad.h"
#include "main/object_transform.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/VF/vf_shared.h"

extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);

/* CameraModeWorldMapState.mode: which world-map camera _update runs */
#define WORLDMAP_CAMERA_FREE_OVERVIEW 0 /* C-stick orbit + focus blend */
#define WORLDMAP_CAMERA_LOCKED_PATH   1 /* fixed-pitch path camera + map marker */

#pragma scheduling on
#pragma peephole on
extern CameraModeWorldMapState* gCamWorldMapState;
extern f32 gCamWorldMapDistanceMax;
extern f32 lbl_803E1A28;
extern f32 lbl_803E1A80;

extern u32 getButtonsHeld(int port);

extern u8 padGetCX(int port);
extern u8 padGetCY(int port);
extern void fn_8012DDB8(int mode);
extern f32 lbl_80319DF8[];
extern f32 lbl_803E1A2C;
extern f32 lbl_803E1A30;
extern f32 lbl_803E1A34;
extern f32 lbl_803E1A38;
extern f32 gCamWorldMapDistanceMin;
extern f32 lbl_803E1A44;
extern f32 gCamWorldMapPi;
extern f32 gCamWorldMapAngleScale;
extern f32 lbl_803E1A50;
extern f32 lbl_803E1A54;
extern f32 lbl_803E1A58;
extern f32 lbl_803E1A5C;
extern f32 lbl_803E1A60;
extern f32 lbl_803E1A64;
extern f32 lbl_803E1A68;
extern f32 gCamWorldMapAlphaScale;

#pragma scheduling off
#pragma peephole off
void CameraModeWorldMap_release(void)
{
}

void CameraModeWorldMap_initialise(void)
{
}

void CameraModeWorldMap_init(int* obj)
{
    register u32 bitval;
    if (gCamWorldMapState == NULL)
    {
        gCamWorldMapState = (CameraModeWorldMapState*)mmAlloc(sizeof(CameraModeWorldMapState), 15, 0);
    }
    gCamWorldMapState->distance = gCamWorldMapDistanceMax;
    gCamWorldMapState->distanceVelocity = lbl_803E1A28;
    bitval = 0;
    gCamWorldMapState->mode = bitval;
    gCamWorldMapState->previousMode = bitval;
    gCamWorldMapState->flags.transitionActive = 0;
    gCamWorldMapState->settleFrames = 1;
    gCamWorldMapState->focusBlendTimer = 0;
    gCamWorldMapState->focusObjectId = 0;
    *(f32*)&((GameObject*)obj)->seqIndex = lbl_803E1A80;
    ((GameObject*)obj)->anim.rotX = -32768;
}

void CameraModeWorldMap_copyToCurrent(int* p1, int kind)
{
    switch (kind)
    {
    case 0:
        if (p1 == NULL) return;
        gCamWorldMapState->mode = *(u8*)p1;
        return;
    case 1:
    case 2:
        if (p1 == NULL) return;
        gCamWorldMapState->focusObjectId = *p1;
        if (kind == 1)
        {
            gCamWorldMapState->focusBlendTimer = 20;
        }
        else
        {
            gCamWorldMapState->focusBlendTimer = 1;
        }
        return;
    }
}

void CameraModeWorldMap_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)gCamWorldMapState);
    gCamWorldMapState = NULL;
}

#pragma opt_common_subs off
#pragma opt_propagation off
void CameraModeWorldMap_update(u8* obj)
{
    GameObject* camera = (GameObject*)obj;
    GameObject* focus;
    GameObject *objA, *objB;
    u16 buttons;
    f32 spd = lbl_803E1A28;
    f32 mdx, mdz;
    s16 pitchDelta;

    focus = (GameObject*)camera->anim.targetObj;
    objA = (GameObject*)ObjList_FindObjectById(0x42fff);
    objB = (GameObject*)ObjList_FindObjectById(0x4325b);
    buttons = getButtonsHeld(0);
    getButtonsJustPressed(0);

    switch (gCamWorldMapState->mode)
    {
    case WORLDMAP_CAMERA_FREE_OVERVIEW:
        if (gCamWorldMapState->previousMode != gCamWorldMapState->mode)
        {
            gCamWorldMapState->focusBlendTimer = 1;
            (*gScreenTransitionInterface)->start(0xc, 1);
            gCamWorldMapState->settleFrames = 2;
            gCamWorldMapState->flags.transitionActive = 1;
        }
        else
        {
            s16 dYaw, dPitch;
            if (gCamWorldMapState->flags.transitionActive != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0)
            {
                u8* mk;
                fn_8012DDB8(0);
                (*gScreenTransitionInterface)->step(0xc, 1);
                gCamWorldMapState->flags.transitionActive = 0;
                mk = (u8*)(*(int*)&((GameObject*)ObjList_FindObjectById(0x43077))->extra + 0x27d);
                *mk = 0;
            }
            if (gCamWorldMapState->flags.transitionActive == 0)
            {
                gCamWorldMapState->settleFrames -= 1;
                if (gCamWorldMapState->settleFrames < 1)
                {
                    gCamWorldMapState->settleFrames = 1;
                }
                if (buttons & 8)
                {
                    spd = lbl_803E1A2C * gCamWorldMapState->distance;
                }
                if (buttons & 4)
                {
                    spd = lbl_803E1A30 * gCamWorldMapState->distance;
                }
                {
                    f32 a, b, rate, vel;
                    if (spd < lbl_803E1A28)
                    {
                        a = -spd;
                    }
                    else
                    {
                        a = spd;
                    }
                    vel = gCamWorldMapState->distanceVelocity;
                    if (vel < lbl_803E1A28)
                    {
                        b = -vel;
                    }
                    else
                    {
                        b = vel;
                    }
                    if (b > a)
                    {
                        rate = lbl_803E1A34;
                    }
                    else
                    {
                        rate = lbl_803E1A38;
                    }
                    gCamWorldMapState->distanceVelocity =
                        rate * (spd - vel) + gCamWorldMapState->distanceVelocity;
                }
                gCamWorldMapState->distance = gCamWorldMapState->distance + gCamWorldMapState->distanceVelocity;
                if (gCamWorldMapState->distance < gCamWorldMapDistanceMin)
                {
                    gCamWorldMapState->distance = gCamWorldMapDistanceMin;
                }
                if (gCamWorldMapState->distance > gCamWorldMapDistanceMax)
                {
                    gCamWorldMapState->distance = gCamWorldMapDistanceMax;
                }
                dYaw = (s16)((s8)padGetCX(0) * 3);
                dPitch = (s16)((s8)padGetCY(0) * 3);
                if (gCamWorldMapState->focusBlendTimer != 0)
                {
                    GameObject* f = (GameObject*)ObjList_FindObjectById(gCamWorldMapState->focusObjectId);
                    f32 dx = f->anim.worldPosX - objA->anim.worldPosX;
                    f32 dz = f->anim.worldPosZ - objA->anim.worldPosZ;
                    CameraModeWorldMapState* st;
                    s16 angleDelta;
                    f32 cur;
                    gCamWorldMapState->targetAngle = (s16)(0x8000 - getAngle(dx, dz));
                    angleDelta = (s16)((st = gCamWorldMapState)->targetAngle - (u16)camera->anim.rotX);
                    if (angleDelta > 0x8000)
                    {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000)
                    {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + angleDelta / st->focusBlendTimer;
                    gCamWorldMapState->targetAngle =
                        (s16)(0x47d0 - getAngle(sqrtf(dx * dx + dz * dz),
                                                f->anim.worldPosY - objA->anim.worldPosY));
                    angleDelta = (s16)((st = gCamWorldMapState)->targetAngle - (u16)camera->anim.rotY);
                    if (angleDelta > 0x8000)
                    {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000)
                    {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + angleDelta / st->focusBlendTimer;
                    st = gCamWorldMapState;
                    cur = st->distance;
                    st->distance =
                        cur + (f32)((s16)(s32)(lbl_803E1A44 - cur) /
                            st->focusBlendTimer);
                    gCamWorldMapState->focusBlendTimer -= 1;
                }
                camera->anim.rotX += dYaw;
                camera->anim.rotY += dPitch;
                if (camera->anim.rotY > 12000)
                {
                    camera->anim.rotY = 12000;
                }
                if (camera->anim.rotY < -12000)
                {
                    camera->anim.rotY = -12000;
                }
                {
                    f32 snYaw, csYaw, snPit, csPit;
                    f32 r, vy, h, px, pz;
                    f32 dxx, dyy, dzz;
                    snYaw = -mathCosf(gCamWorldMapPi * camera->anim.rotX / gCamWorldMapAngleScale);
                    csYaw = mathSinf(gCamWorldMapPi * camera->anim.rotX / gCamWorldMapAngleScale);
                    snPit = mathCosf(gCamWorldMapPi * (f32)(camera->anim.rotY + 0x320) / gCamWorldMapAngleScale);
                    csPit = mathSinf(gCamWorldMapPi * (f32)(camera->anim.rotY + 0x320) /
                        gCamWorldMapAngleScale);
                    r = gCamWorldMapState->distance;
                    vy = r * csPit;
                    h = r * snPit;
                    px = h * csYaw;
                    pz = h * snYaw;
                    dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                    dyy = camera->anim.worldPosY - ((lbl_803E1A50 + focus->anim.worldPosY) + vy);
                    dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                    camera->anim.worldPosX =
                        camera->anim.worldPosX - dxx / gCamWorldMapState->settleFrames;
                    camera->anim.worldPosY =
                        camera->anim.worldPosY - dyy / gCamWorldMapState->settleFrames;
                    camera->anim.worldPosZ =
                        camera->anim.worldPosZ - dzz / gCamWorldMapState->settleFrames;
                }
            }
        }
        break;
    case WORLDMAP_CAMERA_LOCKED_PATH:
        {
            GameObject* g = (GameObject*)ObjList_FindObjectById(0x43077);
            if (gCamWorldMapState->previousMode != gCamWorldMapState->mode)
            {
                (*gScreenTransitionInterface)->start(0xc, 1);
                gCamWorldMapState->settleFrames = 2;
                gCamWorldMapState->flags.transitionActive = 1;
            }
            else
            {
                if (gCamWorldMapState->flags.transitionActive != 0 &&
                    (*gScreenTransitionInterface)->isFinished() != 0)
                {
                    u8* mk;
                    fn_8012DDB8(1);
                    (*gScreenTransitionInterface)->step(0xc, 1);
                    gCamWorldMapState->flags.transitionActive = 0;
                    mk = (u8*)(*(int*)&((GameObject*)ObjList_FindObjectById(0x43077))->extra + 0x27d);
                    *mk = 1;
                }
                if (gCamWorldMapState->flags.transitionActive == 0)
                {
                    int ang;
                    s16 angleDelta;
                    u16 my;
                    gCamWorldMapState->settleFrames -= 1;
                    if (gCamWorldMapState->settleFrames < 1)
                    {
                        gCamWorldMapState->settleFrames = 1;
                    }
                    ang = (u16) - getAngle(objA->anim.worldPosX - focus->anim.worldPosX,
                                           objA->anim.worldPosZ - focus->anim.worldPosZ);
                    angleDelta = (s16)((ang - 0x308f) - (u16)camera->anim.rotX);
                    if (angleDelta > 0x8000)
                    {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000)
                    {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + angleDelta / gCamWorldMapState->settleFrames;
                    angleDelta = (s16)(0x7d0 - (u16)camera->anim.rotY);
                    if (angleDelta > 0x8000)
                    {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000)
                    {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + angleDelta / gCamWorldMapState->settleFrames;
                    {
                        f32 a, sn, cs, sn54, cs54;
                        f32 t6, t5, px, pz;
                        f32 dxx, dyy, dzz;
                        a = gCamWorldMapPi * (f32)(u16)(ang - 0x39dc) / gCamWorldMapAngleScale;
                        sn = -mathCosf(a);
                        cs = mathSinf(a);
                        sn54 = mathCosf(lbl_803E1A54);
                        cs54 = mathSinf(lbl_803E1A54);
                        t6 = lbl_803E1A58 * cs54;
                        t5 = lbl_803E1A58 * sn54;
                        px = t5 * cs;
                        pz = t5 * sn;
                        dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                        dyy = camera->anim.worldPosY -
                            (lbl_803E1A5C + (focus->anim.worldPosY + t6));
                        dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                        camera->anim.worldPosX =
                            camera->anim.worldPosX - dxx / gCamWorldMapState->settleFrames;
                        camera->anim.worldPosY =
                            camera->anim.worldPosY - dyy / gCamWorldMapState->settleFrames;
                        camera->anim.worldPosZ =
                            camera->anim.worldPosZ - dzz / gCamWorldMapState->settleFrames;
                    }
                    my = (u16)(camera->anim.rotX + 0x1388);
                    if (isWidescreen() != 0)
                    {
                        my = (u16)(my + 0x514);
                    }
                    {
                        f32 b = gCamWorldMapPi * my / gCamWorldMapAngleScale;
                        f32 sb = mathCosf(b);
                        f32 cb = -mathSinf(b);
                        f32 radius = lbl_803E1A60;
                        g->anim.localPosX = radius * cb + camera->anim.worldPosX;
                        g->anim.localPosY =
                            camera->anim.worldPosY + lbl_80319DF8[(s8) * &g->anim.bankIndex];
                        g->anim.localPosZ = radius * sb + camera->anim.worldPosZ;
                        g->anim.rotX = (s16)(-0xbb8 - my);
                    }
                }
            }
            break;
        }
    }

    gCamWorldMapState->previousMode = gCamWorldMapState->mode;
    {
        GameObject* marker = (GameObject*)ObjList_FindObjectById(0x431dc);
        mdx = marker->anim.worldPosX - camera->anim.worldPosX;
        mdz = marker->anim.worldPosZ - camera->anim.worldPosZ;
        marker->anim.rotX = (s16)(getAngle(mdx, mdz) + 0x8000);
        marker->anim.rotY = (s16)(0x8000 - getAngle(sqrtf(mdx * mdx + mdz * mdz),
                                                    marker->anim.worldPosY - camera->anim.worldPosY));
        marker->anim.rootMotionScale = lbl_803E1A64 + lbl_803E1A68 / gCamWorldMapState->distance;
        objB->anim.rotX = marker->anim.rotX;
        objB->anim.rotY = marker->anim.rotY;
        objB->anim.rootMotionScale = marker->anim.rootMotionScale;
    }

    pitchDelta = (s16)(objB->anim.rotX - 0x2198);
    if (pitchDelta > -0x2000 && pitchDelta < 0x2000)
    {
        f32 lim;
        lim = (lbl_803E1A28 >
            gCamWorldMapAlphaScale *
            (mathCosf(gCamWorldMapPi * (f32)((objB->anim.rotX - 0x2198) * 2) / gCamWorldMapAngleScale) *
                mathCosf(gCamWorldMapPi * (f32)((objB->anim.rotY - 0x4000) * 2) / gCamWorldMapAngleScale)))
            ? lbl_803E1A28
            : gCamWorldMapAlphaScale *
            (mathCosf(gCamWorldMapPi * (f32)((objB->anim.rotX - 0x2198) * 2) / gCamWorldMapAngleScale) *
                mathCosf(gCamWorldMapPi * (f32)((objB->anim.rotY - 0x4000) * 2) / gCamWorldMapAngleScale));
        objB->anim.alpha = lim;
    }
    else
    {
        objB->anim.alpha = 0;
    }

    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}
#pragma opt_propagation reset
#pragma opt_common_subs reset
