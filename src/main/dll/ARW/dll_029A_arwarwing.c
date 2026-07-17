/*
 * arwarwing (DLL 0x29A) - the player's Arwing in the on-rails flight
 * sections. This is the core object of the section; the singleton instance
 * is published through the gArwing global (getArwing) so the pickups,
 * squadron and level-controller TUs can find it.
 *
 * Per-object extra state is ArwingState (arwing_state.h, 0x498 bytes). The
 * update loop reads the controller, integrates flight physics toward stick-
 * driven velocity / rotation targets, runs the laser and bomb weapons, the
 * barrel-roll / wing-flex model rigging, the engine sound and the camera
 * push, then applies path and object damage. A small "mode" state machine
 * covers normal flight, barrel roll, death (4), explode (5) and warp-out
 * (6). arwarwing_init wires up the path-control block and per-course flight
 * tuning (keyed by mapEventSlot); arwarwing_initAttachments locates and
 * links the gun / bomb / engine child models and the wing light before the
 * Arwing becomes active (flags477 bit 1).
 *
 * arwarwing_SeqFn handles object-sequence events: course warps, spawning
 * lasers / bombs / boss objects, aim-snapshot capture for the hit-detect
 * pass, score registration and the per-course map-event setup.
 *
 * Most functions take the extra pointer as a raw int ("state") and cast at
 * each use - that spelling reproduces the retail register colouring; see the
 * CLAUDE.md matching notes.
 */
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/map_load.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/loaded_file_flags.h"
#include "main/mapEventTypes.h"
#include "main/model_light.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/screen_transition.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/maketex_sequence_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/headdisplay.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objprint_api.h"
#include "main/modellight_api.h"
#include "main/objfx.h"
#include "main/object_api.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebit_ids.h"

#include "main/dll/ARW/arwing_state.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"

GameObject* gArwing;
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/object_render_legacy.h"

u8 gArwingCourseMapIds[8] = {7, 0x13, 0x0D, 0x0C, 2, 0, 0, 0};

const ArwInitCfg gArwingInitConfig = {0x05030303, 0x03030303, 0x0303};

typedef struct ArwarwingState
{
    u8 pad0[0x47C - 0x0];
    u16 bonusScore; /* 0x47C: bonus score, +200 per pickup, capped at 9999 */
    u8 pad47E[0x498 - 0x47E];
} ArwarwingState;

typedef struct ArwInitCfgAB
{
    int a;
    int b;
} ArwInitCfgAB;

typedef struct ArwArwingProjectileSetup
{
    s16 objectId;
    u8 pad02[2];
    u8 field04;
    u8 field05;
    u8 pad06[2];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[4];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
} ArwArwingProjectileSetup;

STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, field04) == 0x04);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, field05) == 0x05);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posY) == 0x0c);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, posZ) == 0x10);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwArwingProjectileSetup, rotZ) == 0x1a);

typedef struct ArwArwingVec3
{
    f32 x;
    f32 y;
    f32 z;
} ArwArwingVec3;

STATIC_ASSERT(offsetof(ArwArwingVec3, x) == 0x0);
STATIC_ASSERT(offsetof(ArwArwingVec3, y) == 0x4);
STATIC_ASSERT(offsetof(ArwArwingVec3, z) == 0x8);

#define ARWARWING_OBJGROUP 0x26

#define ARWARWING_OBJFLAG_PARENT_SLACK 0x1000

#define ARWARWING_CHILD_OBJ_LASERSHOT      0x604
#define ARWARWING_CHILD_OBJ_BOMB_PROJECTILE 0x605
#define ARWARWING_CHILD_OBJ_THRUSTER       0x6de
#define ARWARWING_CHILD_OBJ_BOMB           0x608

#define PAD_TRIGGER_R 0x20
#define PAD_TRIGGER_L 0x40
#define PAD_BUTTON_B  0x200

/* Damage partfx emitted in arwarwing_emitDamageEffects, keyed on health. */
#define ARWARWING_PARTFX_DAMAGE   0x7d0 /* health <= 4, every other frame */
#define ARWARWING_PARTFX_CRITICAL 0x7d1 /* health <= 2 (critical) */

/* cross-map destination: Krazoa shrine (0xb) map-event advanced (act 5)
   before warping out at end of the Arwing course; see setObjGroupStatus(0xb,..) */
#define ARWARWING_MAPEVENT_SHRINE 0xb

/* ArwingState.flags477 bits */
#define ARWING_FLAG_ACTIVE     0x1 /* Arwing is active / engaged */
#define ARWING_FLAG_ROLL_LEFT  0x2 /* barrel-rolling left */
#define ARWING_FLAG_ROLL_RIGHT 0x4 /* barrel-rolling right */
#define ARWING_FLAG_ROLLING    0x6 /* ROLL_LEFT | ROLL_RIGHT */

/* ArwingState.mode - the flight state machine. Mode 0 is normal flight
   (never compared against a literal); the others are explicit. */
enum
{
    ARWING_MODE_BARRELROLL = 1,
    ARWING_MODE_DEAD = 4,
    ARWING_MODE_EXPLODE = 5,
    ARWING_MODE_WARPOUT = 6
};

int gArwingPathSetupData[30] = {
    0,           0,           0,           1103626240,  -1073741824, -1038090240, -1043857408, -1073741824,
    -1038090240, 0,           0,           1110179840,  1095761920,  0,           -1049624576, -1051721728,
    0,           -1049624576, 1102577664,  0,           -1041235968, -1044905984, 0,           -1041235968,
    1095761920,  1097859072,  -1044381696, -1051721728, 1097859072,  -1044381696,
};

int sArwingPathName[] = {
    1097859072, 1082130432, 1082130432, 1082130432, 1092616192,
    1092616192, 1092616192, 1092616192, 1084227584, 1084227584,
};

f32 lbl_8032B4A8[30] = {
    0.0f, 0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f, 0.9f,
    1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
};

ObjectDescriptor gARWArwingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)arwarwing_initialise,
    (ObjectDescriptorCallback)arwarwing_release,
    NULL,
    (ObjectDescriptorCallback)arwarwing_init,
    (ObjectDescriptorCallback)arwarwing_update,
    (ObjectDescriptorCallback)arwarwing_hitDetect,
    (ObjectDescriptorCallback)arwarwing_render,
    (ObjectDescriptorCallback)arwarwing_free,
    (ObjectDescriptorCallback)arwarwing_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)arwarwing_getExtraSize,
};

#pragma dont_inline off
static inline f32 clampPos(f32 v, f32 lo, f32 hi)
{
    return (v < lo) ? lo : ((v > hi) ? hi : v);
}

static inline f32 clampNeg(f32 v, f32 lo, f32 hi)
{
    return (v < lo) ? lo : ((v > hi) ? hi : v);
}

static inline f32 arwarwing_readTriggerL(void)
{
    return -(f32)(u32)(u8)padGetLTrigger(0) / 150.0f;
}

void arwarwing_readControls(GameObject* obj, ArwingState* state)
{
    ArwingState* aw = state;
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    aw->stickX = (f32)(s8)padGetStickX(0) / 72.0f;
    aw->stickY = (f32)(s8)padGetStickY(0) / 72.0f;
    if (aw->damageFlashTimer > 0.0f)
    {
        f32 zero = 0.0f;
        nx = -aw->knockVelX;
        ny = -aw->knockVelZ;
        aw->damageFlashTimer = aw->damageFlashTimer - timeDelta;
        tv = lbl_8032B4A8[(int)aw->damageFlashTimer];
        if (aw->damageFlashTimer <= zero)
        {
            aw->hitShake = 0;
            (*gPathControlInterface)->attachObject((void*)obj, aw->pathBlock);
        }
        {
            f32 inv;
            aw->stickX = aw->stickX * (inv = 1.0f - tv) + nx * tv;
            aw->stickY = aw->stickY * inv + ny * tv;
        }
    }
    aw->rTriggerTrim = (f32)(u8)padGetRTrigger(0) / 150.0f;
    aw->rTriggerTrim = clampPos(aw->rTriggerTrim, 0.0f, 1.0f);
    aw->lTriggerTrim = -(f32)(u8)padGetLTrigger(0) / 150.0f;
    aw->lTriggerTrim = clampNeg(aw->lTriggerTrim, -1.0f, 0.0f);
    aw->inputFlags = getButtonsJustPressed(0);
    aw->inputFlagsPrev = getButtonsJustPressedIfNotBusy(0);
    aw->inputFlags2 = getButtonsHeld(0);
    if (aw->mode == 0)
    {
        btn = aw->inputFlags;
        if ((btn & PAD_TRIGGER_R) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_arwingflyby);
            aw->mode = 1;
            aw->barrelRollAngle = (obj)->anim.rotZ;
            aw->barrelRollDirection = aw->barrelRollSpeed;
            aw->barrelRollSpeedScale = 1.0f;
            aw->maxSpeedX = aw->maxSpeedX * aw->barrelRollMaxSpeedScale;
            aw->accelX = aw->accelX * aw->barrelRollAccelScale;
            arwarwingbo_setActiveVisible((GameObject*)(aw->bombObj), 1, 0);
        }
        else if ((btn & PAD_TRIGGER_L) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_arwingflyby);
            aw->mode = 1;
            aw->barrelRollAngle = (obj)->anim.rotZ;
            aw->barrelRollDirection = -aw->barrelRollSpeed;
            aw->barrelRollSpeedScale = 1.0f;
            aw->maxSpeedX = aw->maxSpeedX * aw->barrelRollMaxSpeedScale;
            aw->accelX = aw->accelX * aw->barrelRollAccelScale;
            arwarwingbo_setActiveVisible((GameObject*)(aw->bombObj), 1, 1);
        }
    }
}

void arwarwing_updateThrusters(GameObject* obj, ArwingState* state)
{

    CameraViewSlot* slot;
    f32 mtx[16];
    MatrixTransform src;

    slot = Camera_GetCurrentViewSlot();
    src.x = obj->anim.localPosX;
    src.y = obj->anim.localPosY;
    src.z = obj->anim.localPosZ;
    src.rotX = obj->anim.rotX;
    src.rotY = obj->anim.rotY;
    src.rotZ = 0;
    src.scale = 1.0f;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(
        mtx, 0.0f, 0.0f, lbl_803E6EF0, &state->thrusterL->anim.localPosX,
        &state->thrusterL->anim.localPosY, &state->thrusterL->anim.localPosZ);
    state->thrusterL->anim.worldPosX = state->thrusterL->anim.localPosX;
    state->thrusterL->anim.worldPosY = state->thrusterL->anim.localPosY;
    state->thrusterL->anim.worldPosZ = state->thrusterL->anim.localPosZ;
    state->thrusterL->anim.rotZ = -slot->roll;
    state->thrusterL->anim.rotY = -slot->pitch;
    state->thrusterL->anim.rotX = 0x8000 - slot->yaw;

    Matrix_TransformPoint(
        mtx, 0.0f, 0.0f, lbl_803E6EF4, &state->thrusterR->anim.localPosX,
        &state->thrusterR->anim.localPosY, &state->thrusterR->anim.localPosZ);
    state->thrusterR->anim.worldPosX = state->thrusterR->anim.localPosX;
    state->thrusterR->anim.worldPosY = state->thrusterR->anim.localPosY;
    state->thrusterR->anim.worldPosZ = state->thrusterR->anim.localPosZ;
    state->thrusterR->anim.rotZ = -slot->roll;
    state->thrusterR->anim.rotY = -slot->pitch;
    state->thrusterR->anim.rotX = 0x8000 - slot->yaw;
}

#pragma dont_inline on
#pragma opt_propagation off
void arwarwing_updateBarrelRoll(GameObject* obj, ArwingState* state)
{
    f32 zero;
    f32 direction;

    state->barrelRollAngle =
        (int)(timeDelta * (state->barrelRollDirection * state->barrelRollSpeedScale) +
              (f32)state->barrelRollAngle);
    obj->anim.rotZ =
        (s16)(timeDelta * (state->barrelRollDirection * state->barrelRollSpeedScale) +
              (f32) * &obj->anim.rotZ);
    direction = state->barrelRollDirection;
    zero = 0.0f;
    if (direction > zero)
    {
        {
            int tgt = state->rotZTrimCur;
            int angle;
            int hi = tgt + 0xffff;
            int mid = tgt + 0x8000;
            angle = state->barrelRollAngle;
            if (angle > hi)
            {
                state->mode = 0;
                state->rotZTrimCur = state->barrelRollAngle - 0xffff;
                state->rotZBlend = zero;
                state->maxSpeedX =
                    state->maxSpeedX / state->barrelRollMaxSpeedScale;
                state->accelX =
                    state->accelX / state->barrelRollAccelScale;
                arwarwingbo_setActiveVisible((GameObject*)(state->bombObj), 0, 0);
            }
            else if (angle > mid)
            {
                int d = angle - (u16)tgt;
                if (d > 0x8000)
                    d -= 0xffff;
                if (d < -0x8000)
                    d += 0xffff;
                if (d < 0)
                    d = -d;
                state->barrelRollSpeedScale = d / state->barrelRollDecelRange;
                if (state->barrelRollSpeedScale < lbl_803E6EF8)
                    state->barrelRollSpeedScale = lbl_803E6EF8;
                else if (state->barrelRollSpeedScale > 1.0f)
                    state->barrelRollSpeedScale = 1.0f;
            }
        }
    }
    else
    {
        {
            int tgt = state->rotZTrimCur;
            int angle;
            int lo = tgt - 0xffff;
            int mid = tgt - 0x8000;
            angle = state->barrelRollAngle;
            if (angle < lo)
            {
                state->mode = 0;
                state->rotZTrimCur = state->barrelRollAngle + 0xffff;
                state->rotZBlend = zero;
                state->maxSpeedX =
                    state->maxSpeedX / state->barrelRollMaxSpeedScale;
                state->accelX =
                    state->accelX / state->barrelRollAccelScale;
                arwarwingbo_setActiveVisible((GameObject*)(state->bombObj), 0, 0);
            }
            else if (angle > mid)
            {
                int d = angle - (u16)tgt;
                if (d > 0x8000)
                    d -= 0xffff;
                if (d < -0x8000)
                    d += 0xffff;
                if (d < 0)
                    d = -d;
                state->barrelRollSpeedScale = d / state->barrelRollDecelRange;
                if (state->barrelRollSpeedScale < lbl_803E6EF8)
                    state->barrelRollSpeedScale = lbl_803E6EF8;
                else if (state->barrelRollSpeedScale > 1.0f)
                    state->barrelRollSpeedScale = 1.0f;
            }
        }
    }
}
#pragma opt_propagation reset

void arwarwing_clampToFlightBounds(GameObject* obj, ArwingState* state)
{
    ArwingState* arwing = state;
    f32 hy;
    f32 lx;
    f32 hx;
    f32 ly;
    hx = arwing->homeX + arwing->flightHalfWidth;
    lx = arwing->homeX - arwing->flightHalfWidth;
    hy = arwing->homeY + arwing->flightUpperHeight;
    ly = arwing->homeY - arwing->flightLowerHeight;
    if (obj->anim.localPosX > hx)
    {
        obj->anim.localPosX = hx;
        arwing->velX = 0.0f;
    }
    else if (obj->anim.localPosX < lx)
    {
        obj->anim.localPosX = lx;
        arwing->velX = 0.0f;
    }
    if (obj->anim.localPosY > hy)
    {
        obj->anim.localPosY = hy;
        arwing->velY = 0.0f;
    }
    else if (obj->anim.localPosY < ly)
    {
        obj->anim.localPosY = ly;
        arwing->velY = 0.0f;
    }
    arwing->camPos[0] = obj->anim.localPosX - arwing->homeX;
    arwing->camPos[1] = obj->anim.localPosY - arwing->homeY;
    arwing->camPos[2] = 0.0f;
}

void arwarwing_updateFlightPhysics(GameObject* obj, ArwingState* state)
{
    ArwingState* arwing = state;
    f32 v[3];
    f32 cz;
    int diff;
    int iv;

    if ((obj)->anim.mapEventSlot == 0x26)
    {
        arwing->velTargetZ = 0.0f;
    }
    PSVECSubtract((const Vec*)&arwing->velTargetX, (const Vec*)&arwing->velX, (Vec*)v);
    v[0] = v[0] * arwing->accelX;
    v[1] = v[1] * arwing->accelY;
    v[2] = v[2] * arwing->accelZ;
    v[2] = v[2] < arwing->minAccelZ ? arwing->minAccelZ : (v[2] > arwing->maxAccelZ ? arwing->maxAccelZ : v[2]);
    PSVECScale((const Vec*)v, (Vec*)v, timeDelta);
    PSVECAdd((const Vec*)&arwing->velX, (const Vec*)v, (Vec*)&arwing->velX);
    objMove((GameObject*)obj, arwing->velX * timeDelta, arwing->velY * timeDelta, arwing->velZ * timeDelta);

    diff = arwing->rotXTarget - (u16)arwing->rotXCur;
    if (diff > 0x8000)
        diff = diff - 0xffff;
    if (diff < -0x8000)
        diff = diff + 0xffff;
    iv = (int)(f32)((int)((f32)diff * arwing->rotXGain) - arwing->rotXRate);
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    arwing->rotXRate = (int)((f32)iv * timeDelta + (f32)((ArwingState*)arwing)->rotXRate);
    arwing->rotXCur = (int)((f32)arwing->rotXRate * timeDelta + arwing->rotXCur);

    diff = arwing->rotYTarget - (u16)arwing->rotYCur;
    if (diff > 0x8000)
        diff = diff - 0xffff;
    if (diff < -0x8000)
        diff = diff + 0xffff;
    iv = (int)(f32)((int)((f32)diff * arwing->rotYGain) - arwing->rotYRate);
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    arwing->rotYRate = (int)((f32)iv * timeDelta + (f32)((ArwingState*)arwing)->rotYRate);
    arwing->rotYCur = (int)((f32)arwing->rotYRate * timeDelta + arwing->rotYCur);

    diff = arwing->rotZTarget - (u16)arwing->rotZCur;
    if (diff > 0x8000)
        diff = diff - 0xffff;
    if (diff < -0x8000)
        diff = diff + 0xffff;
    iv = (int)((f32)(int)((f32)diff * arwing->rotZGain) - arwing->rotZRate);
    iv = (iv < -0x64) ? -0x64 : ((iv > 0x64) ? 0x64 : iv);
    arwing->rotZRate = iv * timeDelta + ((ArwingState*)arwing)->rotZRate;
    arwing->rotZCur = (int)(arwing->rotZRate * timeDelta + arwing->rotZCur);

    if (arwing->mode == 0)
    {
        diff = arwing->rotZTrimTarget - (u16)arwing->rotZTrimCur;
        if (diff > 0x8000)
            diff = diff - 0xffff;
        if (diff < -0x8000)
            diff = diff + 0xffff;
        arwing->rotZTrimCur =
            (int)(timeDelta * ((f32)diff * arwing->rotZTrimGain) + (f32)((ArwingState*)arwing)->rotZTrimCur);
        if ((f32)arwing->rotZTrimCur > arwing->rotZBlendThreshold || arwing->rotZTrimCur < -arwing->rotZBlendThreshold)
        {
            arwing->rotZBlend = arwing->rotZBlend - arwing->rotZBlendRate * timeDelta;
        }
        else
        {
            arwing->rotZBlend = arwing->rotZBlendRate * timeDelta + arwing->rotZBlend;
        }
    }
    else
    {
        arwing->rotZBlend = arwing->rotZBlend - arwing->rotZBlendRate * timeDelta;
    }
    if (arwing->rotZBlend < 0.0f)
    {
        arwing->rotZBlend = 0.0f;
    }
    else if (arwing->rotZBlend > 1.0f)
    {
        arwing->rotZBlend = 1.0f;
    }

    (obj)->anim.rotX = arwing->rotXCur;
    (obj)->anim.rotY = arwing->rotYCur;
    if (arwing->mode == 1)
    {
        arwarwing_updateBarrelRoll(obj, state);
    }
    else
    {
        (obj)->anim.rotZ = ((f32)arwing->rotZCur * arwing->rotZBlend + arwing->rotZTrimCur);
        if ((obj)->anim.rotZ < -0x4000)
        {
            (obj)->anim.rotZ = -0x4000;
        }
        else if ((obj)->anim.rotZ > 0x4000)
        {
            (obj)->anim.rotZ = 0x4000;
        }
    }

    if (sqrtf(arwing->velX * arwing->velX + arwing->velY * arwing->velY) < arwing->bobSpeedThreshold &&
        arwing->mode == 0)
    {
        arwing->bobBlend = arwing->bobBlendRate * timeDelta + arwing->bobBlend;
    }
    else
    {
        arwing->bobBlend = arwing->bobBlend - arwing->bobBlendRate * timeDelta;
    }
    if (arwing->bobBlend < 0.0f)
    {
        arwing->bobBlend = 0.0f;
    }
    else if (arwing->bobBlend > 1.0f)
    {
        arwing->bobBlend = 1.0f;
    }

    (obj)->anim.rotZ = (arwing->bobBlend * (arwing->bobRotZAmp *
                                            mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobRotZPhase / lbl_803E6F00)) +
                        (f32) * &(obj)->anim.rotZ);
    (obj)->anim.localPosX =
        arwing->bobBlend * (arwing->bobXAmp * mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobXPhase / lbl_803E6F00)) +
        (obj)->anim.localPosX;
    (obj)->anim.localPosY =
        arwing->bobBlend * (arwing->bobYAmp * mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobYPhase / lbl_803E6F00)) +
        (obj)->anim.localPosY;
    arwing->bobRotZPhase = (arwing->bobRotZRate * timeDelta + (f32)(u32)arwing->bobRotZPhase);
    arwing->bobXPhase = (arwing->bobXRate * timeDelta + (f32)(u32)arwing->bobXPhase);
    arwing->bobYPhase = (arwing->bobYRate * timeDelta + (f32)(u32)arwing->bobYPhase);
    arwarwing_clampToFlightBounds(obj, state);
}

#pragma dont_inline off
void arwarwing_spawnBomb(GameObject* obj, ArwingState* state, int side)
{
    ArwingState* arwing = state;
    f32 pz, py, px;
    ArwingBombSetup* setup;
    u8 cnt;
    if (Obj_IsLoadingLocked() == 0)
        return;
    cnt = arwing->bombCount;
    if (cnt == 0)
        return;
    arwing->bombCount--;
    if (side == 0)
        ObjPath_GetPointWorldPosition(obj, 5, &px, &py, &pz, 0);
    else
        ObjPath_GetPointWorldPosition(obj, 6, &px, &py, &pz, 0);
    setup = (ArwingBombSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_BOMB_PROJECTILE);
    ((ArwingBombSetup*)setup)->head.posX = px;
    ((ArwingBombSetup*)setup)->head.posY = py;
    ((ArwingBombSetup*)setup)->head.posZ = pz;
    ((ArwingBombSetup*)setup)->yaw = (obj)->anim.rotX >> 8;
    ((ArwingBombSetup*)setup)->pitch = (obj)->anim.rotY >> 8;
    ((ArwingBombSetup*)setup)->roll = (obj)->anim.rotZ >> 8;
    ((ArwingBombSetup*)setup)->head.color[0] = 1;
    ((ArwingBombSetup*)setup)->head.color[1] = 1;
    arwing->activeBombObj = loadObjectAtObject(obj, &setup->base);
    fn_8022ED74(arwing->activeBombObj, *(u16*)&arwing->bombProjectileParam);
    fn_8022ECE0(arwing->activeBombObj, arwing->bombProjectileLifetime);
    Sfx_PlayFromObject((int)obj, SFXTRIG_ar_badhit16);
}

#pragma dont_inline on
void arwarwing_updateBombFire(GameObject* obj, ArwingState* state)
{
    ArwingState* arwing = state;
    if (arwing->activeBombObj != NULL)
        return;
    {
        f32 t = arwing->bombCooldown;
        f32 zero = 0.0f;
        if (t > zero)
        {
            arwing->bombCooldown = t - timeDelta;
            if (arwing->bombCooldown < zero)
            {
                arwing->bombCooldown = zero;
            }
            else
            {
                return;
            }
        }
    }
    if (arwing->inputFlags & PAD_BUTTON_B)
    {
        if ((s8)arwing->bombVolleyMode == 1)
        {
            arwarwing_spawnBomb(obj, state, 0);
            arwarwing_spawnBomb(obj, state, 1);
        }
        else
        {
            arwarwing_spawnBomb(obj, state, arwing->bombSide);
            arwing->bombSide = (arwing->bombSide ^ 1) & 0xff;
        }
        arwing->bombCooldown = (f32)(u32) * (u16*)&arwing->bombFireDelay;
    }
}

#pragma dont_inline reset

void arwarwing_spawnLaserShot(GameObject* obj, ArwingState* state, int side, int level, int linkEffect)
{
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    if (side == 0)
    {
        ObjPath_GetPointWorldPosition(obj, 3, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(state->gunObjL, 1, level == 2);
    }
    else
    {
        ObjPath_GetPointWorldPosition(obj, 4, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(state->gunObjR, 1, level == 2);
    }
    {
        ArwArwingProjectileSetup* setup =
            (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_LASERSHOT);
        setup->posX = px;
        setup->posY = py;
        setup->posZ = pz;
        setup->rotZ = (obj)->anim.rotX >> 8;
        setup->rotY = (obj)->anim.rotY >> 8;
        setup->rotX = 0;
        setup->field04 = 1;
        setup->field05 = 1;
        proj = (int)loadObjectAtObject(obj, (ObjPlacement*)setup);
    }
    if ((void*)proj == NULL)
        return;
    if (level == 0)
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_brakes16);
    }
    else if (level == 1)
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_englp16);
    }
    else
    {
        Sfx_PlayFromObject(proj, SFXTRIG_ar_deflect16);
        Obj_SetActiveModelIndex((GameObject*)proj, 1);
    }
    if ((u8)linkEffect != 0)
        arwprojectile_createLinkedEffect((GameObject*)(proj), 1);
    arwprojectile_setLifetime((GameObject*)(proj), state->projLifetime);
    arwprojectile_placeForward((GameObject*)(proj), state->projSpeed);
}

#pragma dont_inline on
void arwarwing_updateWeaponFire(GameObject* obj, ArwingState* state)
{
    int fire;
    arwarwing_updateThrusters(obj, state);
    {
        f32 t = state->fireCooldown;
        f32 zero = 0.0f;
        if (t > zero)
        {
            state->fireCooldown = t - timeDelta;
            if (state->fireCooldown < zero)
                state->fireCooldown = zero;
            else
                return;
        }
    }
    fire = 0;
    if (state->inputFlags2 & 0x100)
    {
        state->fireTimer -= timeDelta;
        if (state->fireTimer <= 0.0f)
            fire = 1;
    }
    if ((state->inputFlags & 0x100) == 0 && fire == 0)
        return;
    state->fireTimer = gArwingFireTimerReset;
    if ((s8)state->laserLevel == 2)
    {
        arwarwing_spawnLaserShot(obj, state, 0, 2, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 2, 0);
    }
    else if ((s8)state->laserLevel == 1)
    {
        arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
    }
    else
    {
        arwarwing_spawnLaserShot(obj, state, state->laserSide, 0, 1);
        state->laserSide = (state->laserSide ^ 1) & 0xff;
    }
    state->fireCooldown = (f32)(u32)state->fireDelay;
}
#pragma dont_inline off

void arwarwing_emitDamageEffects(int obj, ArwingState* state)
{
    ArwingState* arwing = state;
    u8 flag;
    struct
    {
        u8 pad[6];
        s16 type;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } emit;
    flag = 0;
    if ((s8)arwing->health <= 4)
    {
        if (arwing->damageEffectCounter++ % 2 != 0)
        {
            emit.a = lbl_803E6F08;
            emit.b = lbl_803E6F0C;
            emit.c = lbl_803E6F10;
            emit.d = lbl_803E6F14;
            if ((s8)arwing->health <= 2)
                emit.type = 0x61a8;
            else
                emit.type = -0x63c0;
            (*gPartfxInterface)->spawnObject((void*)obj, ARWARWING_PARTFX_DAMAGE, &emit.pad, 4, -1, &flag);
        }
    }
    if ((s8)arwing->health <= 2)
    {
        emit.a = lbl_803E6F18;
        emit.type = 0xc0a;
        emit.b = 0.0f;
        emit.c = lbl_803E6F1C;
        emit.d = lbl_803E6F20;
        (*gPartfxInterface)->spawnObject((void*)obj, ARWARWING_PARTFX_CRITICAL, &emit.pad, 4, -1, &flag);
    }
}

void arwarwing_handlePathDamage(GameObject* obj, ArwingState* state)
{
    u8* pathBlock = state->pathBlock;
    int dmg;

    (*gPathControlInterface)->update((void*)obj, pathBlock, timeDelta);
    (*gPathControlInterface)->apply((void*)obj, pathBlock);
    (*gPathControlInterface)->advance((void*)obj, pathBlock, timeDelta);

    if (state->hitShake == 0 || state->mode == ARWING_MODE_DEAD)
    {
        dmg = (s8)pathBlock[0x260];
        if (dmg == 0)
            return;
        if (state->mode == ARWING_MODE_DEAD)
        {
            state->mode = ARWING_MODE_EXPLODE;
            state->modeTimer = gArwingExplodeModeTime;
            (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosionLegacy((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
            return;
        }
        if ((dmg & 1) && (s8)pathBlock[0xb8] == 8)
            state->health = 0;
        else
            state->health--;
        doRumble(lbl_803E6F2C);
        if ((s8)state->health <= 0)
        {
            arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
            if ((obj)->anim.mapEventSlot == 0x26)
                mainSetBits(GAMEBIT_ArwingRelated0E74, 1);
            else
                state->mode = ARWING_MODE_DEAD;
            state->modeTimer = lbl_803E6F30;
            Sfx_PlayFromObject((int)obj, SFXTRIG_barrelblow11);
            Music_Trigger(MUSICTRIG_dark_ice_boss_1, 1);
        }
        else if ((s8)((ArwingState*)(obj)->extra)->health <= 3)
        {
            Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_bomb_pickup);
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_select);
        ((Arw339Flags*)&state->flags339)->scoreFlag = 1;
        Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
        state->damageFlashTimer = lbl_803E6F34;
        state->hitShake = 1;
        state->shakeYaw = 0;
        state->shakePitch = 0;
        state->knockVelX = *(f32*)(pathBlock + 0x1a0);
        state->knockVelZ = *(f32*)(pathBlock + 0x1a4);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E6F38);
    }
    else
    {
        state->shakeYaw = lbl_803E6F3C * timeDelta + (f32) * (u16*)&state->shakeYaw;
        state->shakePitch = lbl_803E6F40 * timeDelta + (f32) * (u16*)&state->shakePitch;
    }
}

#pragma opt_common_subs off
void arwarwing_handleObjectDamage(GameObject* obj, ArwingState* state)
{
    int hitVol;
    int hitObj;

    if (objGetFlagsE5_2((u8*)obj) != 0)
        return;
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, (u32*)&hitVol) != 0 && hitVol != 0)
    {
        if (state->mode == ARWING_MODE_DEAD)
        {
            state->mode = ARWING_MODE_EXPLODE;
            state->modeTimer = gArwingExplodeModeTime;
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosionLegacy((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        else
        {
            if (((GameObject*)hitObj)->anim.seqId == 0x6ae && state->mode == ARWING_MODE_BARRELROLL)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_ar_blaunch16);
                return;
            }
            doRumble(lbl_803E6F2C);
            *(s8*)&state->health = *(s8*)&state->health - hitVol;
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_select_2ac);
            ((Arw339Flags*)&state->flags339)->scoreFlag = 1;
            Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
            state->damageFlashTimer = lbl_803E6F34;
            state->hitShake = 1;
            state->shakeYaw = 0;
            state->shakePitch = 0;
            {
                f32 knock = 0.0f;
                state->knockVelX = knock;
                state->knockVelZ = knock;
            }
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6F2C);
        }
    }
    if (state->mode != ARWING_MODE_DEAD && state->mode != ARWING_MODE_EXPLODE &&
        state->mode != ARWING_MODE_WARPOUT && (s8)state->health <= 0)
    {
        arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
        if (obj->anim.mapEventSlot == 0x26)
            mainSetBits(GAMEBIT_ArwingRelated0E74, 1);
        state->mode = ARWING_MODE_DEAD;
        state->modeTimer = lbl_803E6F30;
        Sfx_PlayFromObject((int)obj, SFXTRIG_barrelblow11);
        Music_Trigger(MUSICTRIG_dark_ice_boss_1, 1);
        unlockLevel(0, 0, 1);
        loadMapAndParent(0x29);
        lockLevel(mapGetDirIdx(0x29), 0);
    }
    else if ((s8)((ArwingState*)obj->extra)->health <= 3)
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_bomb_pickup);
    }
}
#pragma opt_common_subs reset

void arwarwing_updateRollAndEngine(int obj, ArwingState* state)
{
    s16* vec;
    f32 vol;
    f64 sum;

    vec = objModelGetVecFn_800395d8(state->escortObj, 0x14);

    if (state->mode < ARWING_MODE_DEAD && mainGetBit(GAMEBIT_ArwingRelated09D6) == 0 &&
        mainGetBit(GAMEBIT_ARWING_FLIGHT_RINGS_PASSED) == 0)
    {
        sum = lbl_803E6F48 + fn_802945E0(state->velZ / state->maxSpeedZ);
        vol = (f32)(sum * lbl_803E6F50);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_ar_boost16);
        Sfx_SetObjectChannelVolume(obj, 0x40, 0xfe, vol);
    }

    arwarwinggu_setTextureFrame(state->escortObj, state->enginePitch);

    if (state->rollCooldown <= 0.0f)
    {
        if ((state->flags477 & ARWING_FLAG_ROLL_LEFT) == 0)
        {
            if ((state->inputFlags & 0x800) != 0)
            {
                state->flags477 &= ~ARWING_FLAG_ROLL_RIGHT;
                state->flags477 |= ARWING_FLAG_ROLL_LEFT;
                state->wingFlexTarget = lbl_803E6F58;
                Sfx_PlayFromObjectLimited(obj, SFXTRIG_ar_barrel16_2b6, 3);
            }
        }
        else
        {
            state->speedScaleZ = state->speedScaleRollL;
            state->accelZ = state->accelZRollL;
            if ((state->inputFlagsPrev & 0x800) != 0)
            {
                state->flags477 &= ~ARWING_FLAG_ROLL_LEFT;
                state->wingFlexTarget = lbl_803E6F5C;
            }
        }
        if ((state->flags477 & ARWING_FLAG_ROLL_RIGHT) == 0)
        {
            if ((state->inputFlags & 0x400) != 0)
            {
                state->flags477 &= ~ARWING_FLAG_ROLL_LEFT;
                state->flags477 |= ARWING_FLAG_ROLL_RIGHT;
                state->wingFlexTarget = lbl_803E6F60;
                Sfx_PlayFromObjectLimited(obj, SFXTRIG_ar_bblast16, 3);
            }
        }
        else
        {
            state->speedScaleZ = state->speedScaleRollR;
            state->accelZ = state->accelZRollR;
            if ((state->inputFlagsPrev & 0x400) != 0)
            {
                state->flags477 &= ~ARWING_FLAG_ROLL_RIGHT;
                state->wingFlexTarget = lbl_803E6F5C;
            }
        }
    }
    else
    {
        if ((state->inputFlags & 0xc00) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_generic_pickup);
        }
        state->rollCooldown -= timeDelta;
        if (state->rollCooldown <= 0.0f)
        {
            state->wingFlexTarget = lbl_803E6F5C;
        }
    }

    if ((state->flags477 & ARWING_FLAG_ROLLING) == 0)
    {
        state->speedScaleZ = 1.0f;
        state->accelZ = state->accelZNeutral;
        if (state->rollRegenDelay <= 0.0f)
        {
            state->rollEnergy = lbl_803E6F64 * timeDelta + state->rollEnergy;
        }
        else
        {
            state->rollRegenDelay -= timeDelta;
        }
    }
    else
    {
        state->rollEnergy -= timeDelta;
        state->rollRegenDelay = lbl_803E6F38;
    }

    state->rollEnergy = state->rollEnergy < 0.0f
                            ? 0.0f
                            : state->rollEnergy > state->rollEnergyMax ? state->rollEnergyMax : state->rollEnergy;

    {
        f32 zero;
        if (state->rollEnergy <= (zero = 0.0f))
        {
            state->flags477 &= ~ARWING_FLAG_ROLLING;
            state->rollCooldown = state->rollCooldownInit;
            state->rollEnergy = state->rollEnergyMax;
            state->wingFlexTarget = lbl_803E6F68;
            state->rollRegenDelay = zero;
        }
    }

    if (vec != NULL)
    {
        s16 flex;
        state->wingFlexCur +=
            lbl_803E6EF8 * (state->wingFlexTarget - state->wingFlexCur);
        flex = (s16)state->wingFlexCur;
        vec[5] = flex;
        vec[4] = flex;
        vec[3] = flex;
    }
}

void arwarwing_warpByCourse(GameObject* obj)
{
    switch (obj->anim.mapEventSlot)
    {
    case 0x3a:
        if ((u32)mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0)
        {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ARWARWING_MAPEVENT_SHRINE, 5);
            (*gMapEventInterface)->setObjGroupStatus(ARWARWING_MAPEVENT_SHRINE, 0xa, 1);
            (*gMapEventInterface)->setObjGroupStatus(ARWARWING_MAPEVENT_SHRINE, 0xb, 1);
            warpToMap(0x22, 0);
        }
        else
        {
            warpToMap(0x6c, 0);
        }
        break;
    case 0x3b:
        warpToMap(0x77, 0);
        break;
    case 0x3d:
        warpToMap(0x78, 0);
        break;
    case 0x3c:
        warpToMap(0x63, 0);
        break;
    case 0x3e:
        warpToMap(0x79, 0);
        break;
    }
}

void arwarwing_clearAimSnapshot(GameObject* obj)
{
    (*(ArwingState**)&obj->extra)->aimSnapshotValid = 0;
}

#pragma dont_inline on
int arwarwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    ArwingState* state = obj->extra;

    Camera_GetCurrentViewSlot();
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)arwarwing_clearAimSnapshot;
    if ((state->flags477 & ARWING_FLAG_ACTIVE) == 0)
    {
        arwarwing_initAttachments(obj, state);
        return 0;
    }
    arwarwing_updateRollAndEngine((int)obj, state);
    arwarwing_updateThrusters(obj, state);
    if (state->bombObj != NULL)
        arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
    state->thrusterL->anim.flags |= OBJANIM_FLAG_HIDDEN;
    state->thrusterL->anim.alpha = 0;
    state->thrusterR->anim.flags |= OBJANIM_FLAG_HIDDEN;
    state->thrusterR->anim.alpha = 0;
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 8:
        {
            CameraViewSlot* cam = Camera_GetCurrentViewSlot();
            state->aimOffsetX = cam->x - obj->anim.localPosX;
            state->aimOffsetY = cam->y - obj->anim.localPosY;
            state->aimOffsetZ = cam->z - obj->anim.localPosZ;
            state->aimYaw = obj->anim.rotX - (u16)cam->yaw;
            if (state->aimYaw > 32768)
                state->aimYaw = state->aimYaw - 65535;
            if (state->aimYaw < -32768)
                state->aimYaw = state->aimYaw + 65535;
            state->aimPitch = obj->anim.rotY - (u16)cam->pitch;
            if (state->aimPitch > 32768)
                state->aimPitch = state->aimPitch - 65535;
            if (state->aimPitch < -32768)
                state->aimPitch = state->aimPitch + 65535;
            state->aimRoll = cam->roll - obj->anim.rotZ;
            state->aimSnapshotValid = 1;
            break;
        }
        case 9:
            state->aimSnapshotValid = 0;
            break;
        case 1:
            clearLoadedFileFlags_blocks1();
            warpToMap(0x60, 0);
            break;
        case 2:
            clearLoadedFileFlags_blocks1();
            arwarwing_warpByCourse(obj);
            break;
        case 0xa:
            if (Obj_IsLoadingLocked())
            {
                ArwArwingProjectileSetup* setup =
                    (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x24, ARWARWING_CHILD_OBJ_BOMB);
                int loaded;
                setup->posX = obj->anim.localPosX;
                setup->posY = obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                setup->field04 = 1;
                setup->field05 = 1;
                loaded = (int)loadObjectAtObject(obj, (ObjPlacement*)setup);
                if ((void*)loaded != 0)
                    arwbombcoll_setLifetime((GameObject*)(loaded), 0x12c);
            }
            break;
        case 0xb:
            state->bombCount = 1;
            arwarwing_spawnBomb(obj, state, state->bombSide);
            state->bombSide ^= 1;
            break;
        case 0xc:
            arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
            arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
            break;
        case 4:
            unlockLevel(0, 0, 1);
            mapUnload(0, 0x80000000);
            setLoadedFileFlags_blocks1();
            break;
        case 5:
            if (state->levelIndex == 0 && mainGetBit(GAMEBIT_ITEM_Spirit5_Got))
            {
                loadMapAndParent(0xb);
                lockLevel(mapGetDirIdx(0xb), 0);
            }
            else
            {
                loadMapAndParent(gArwingCourseMapIds[state->levelIndex]);
                lockLevel(mapGetDirIdx(gArwingCourseMapIds[state->levelIndex]), 0);
            }
            switch (obj->anim.mapEventSlot)
            {
            case 0x3a:
                break;
            case 0x3b:
                (*gMapEventInterface)->setObjGroupStatus(0x13, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0x13, 0x16, 1);
                break;
            case 0x3d:
                mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xa, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 1);
                mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                break;
            case 0x3c:
                mainSetBits(GAMEBIT_CF_ObjGroups, 0);
                mainSetBits(GAMEBIT_CD_ObjGroups, 0);
                mainSetBits(GAMEBIT_CF_ObjGroups2, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xc, 0, 1);
                mainSetBits(GAMEBIT_CFRelated0D73, 0);
                break;
            case 0x3e:
                mainSetBits(GAMEBIT_DR_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(2, 0xf, 1);
                (*gMapEventInterface)->setObjGroupStatus(2, 0x10, 1);
                mainSetBits(GAMEBIT_DRArwingRelated0E7B, 0);
                mainSetBits(GAMEBIT_DR_FlewTo, 0);
                break;
            }
            break;
        case 6:
            unlockLevel(0, 0, 1);
            loadMapAndParent(0x29);
            lockLevel(mapGetDirIdx(0x29), 0);
            break;
        case 7:
            if (!((Arw339Flags*)&state->flags339)->scoreFlag)
            {
                ArwarwingState* s2 = obj->extra;
                int score47C;
                s2->bonusScore += 0xc8;
                score47C = s2->bonusScore;
                if ((u16)score47C > 0x270f)
                    score47C = 0x270f;
                s2->bonusScore = score47C;
            }
            registerNewScore((s8)state->scoreSlot, state->score,
                             state->collectedRings, 2);
            break;
        case 0xd:
            gameTextFn_80125ba4(0x13);
            break;
        case 0xe:
            gameTextFn_80125ba4(0x14);
            break;
        }
    }
    return 0;
}
#pragma dont_inline off

void arwarwing_initAttachments(GameObject* obj, ArwingState* state)
{
    int found;
    int mev;
    f32 radius;
    f32 c6F7C;
    f32 c6F78;
    f32 c6F74;
    f32 c6FB0;
    f32 c6F5C;
    f32 c6EF0;

    radius = gArwingEscortSearchRadius;
    mev = (int)(*gMapEventInterface)->getCurCharacterState();

    if (state->escortObj == NULL)
    {
        state->escortObj = ObjList_FindNearestObjectByDefNo(obj, 0x606, &radius);
        if (state->escortObj != NULL)
        {
            ObjLink_AttachChild((int)obj, (int)state->escortObj, 0);
        }
    }

    if (state->fullLoadout != 0)
    {
        if (state->bombObj == NULL)
        {
            state->bombObj = ObjList_FindNearestObjectByDefNo(obj, 0x611, &radius);
            if (state->bombObj != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)state->bombObj, 0);
            }
        }
        if (state->gunObjL == NULL)
        {
            state->gunObjL = ObjList_FindNearestObjectByDefNo(obj, 0x610, &radius);
            if (state->gunObjL != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)state->gunObjL, 0);
            }
        }
        if (state->gunObjR == NULL)
        {
            state->gunObjR = ObjList_FindNearestObjectByDefNo(obj, 0x615, &radius);
            if (state->gunObjR != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)state->gunObjR, 0);
            }
        }
    }

    if (state->thrusterL == NULL && state->thrusterR == NULL)
    {
        ArwArwingProjectileSetup* setup;
        setup = (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_THRUSTER);
        setup->field04 = 1;
        setup->field05 = 1;
        state->thrusterL = loadObjectAtObject(obj, (ObjPlacement*)setup);
        setup = (ArwArwingProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWARWING_CHILD_OBJ_THRUSTER);
        setup->field04 = 1;
        setup->field05 = 1;
        state->thrusterR = loadObjectAtObject(obj, (ObjPlacement*)setup);
    }

    found = 0;
    if (state->fullLoadout != 0)
    {
        if (state->light == 0)
        {
            *(int*)&state->light = (int)objCreateLight(obj, 1);
            if (state->light != 0)
            {
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(state->light, 0.0f, lbl_803E6FC4, lbl_803E6FC8);
                lightSetFieldBC_8001db14(state->light, 1);
                modelLightStruct_setDiffuseColor(state->light, 0x28, 0x7d, 0xff, 0);
                modelLightStruct_setDistanceAttenuation(state->light, lbl_803E6FCC, lbl_803E6FD0);
                modelLightStruct_startColorFade(state->light, 1, 1);
                modelLightStruct_setDiffuseTargetColor(state->light, 0x14, 0x64, 0xc8, 0);
            }
        }
        if (state->escortObj != NULL && state->bombObj != NULL &&
            state->gunObjL != NULL && state->gunObjR != NULL)
        {
            found = 1;
        }
    }
    else
    {
        if (state->escortObj != NULL)
        {
            found = 1;
        }
    }

    if (found != 0)
    {
        (*gCameraInterface)->setFocus((void*)obj, 0);
        state->flags477 |= ARWING_FLAG_ACTIVE;
        state->maxSpeedX = lbl_803E6F70;
        state->accelX = (c6F74 = lbl_803E6F74);
        state->maxSpeedY = (c6F78 = lbl_803E6F78);
        state->accelY = (c6F7C = lbl_803E6F7C);
        state->maxSpeedZ = c6F78;
        state->accelZ = c6F7C;
        state->maxAccelZ = lbl_803E6F80;
        state->minAccelZ = lbl_803E6F84;
        state->speedScaleZ = 1.0f;
        state->rotXRange = lbl_803E6F88;
        state->rotXGain = c6F74;
        state->rotYRange = lbl_803E6F8C;
        state->rotYGain = c6F7C;
        state->rotZRange = lbl_803E6F90;
        state->rotZGain = lbl_803E6F94;
        state->rotZTrimRange = lbl_803E6F98;
        state->rotZTrimGain = lbl_803E6F9C;
        state->rotZBlendThreshold = lbl_803E6FA0;
        state->rotZBlendRate = lbl_803E6FA4;
        state->barrelRollSpeed = lbl_803E6FA8;
        state->unk3FA = 0x19;
        state->barrelRollDecelRange = lbl_803E6FAC;
        state->rootMotionScale = (c6FB0 = lbl_803E6FB0);
        (obj)->anim.rootMotionScale = c6FB0;
        state->barrelRollMaxSpeedScale = lbl_803E6FB4;
        state->barrelRollAccelScale = lbl_803E6FB8;
        state->speedScaleRollL = lbl_803E6FBC;
        state->speedScaleRollR = lbl_803E6F64;
        state->accelZRollL = lbl_803E6FD4;
        state->accelZRollR = c6F74;
        state->accelZNeutral = lbl_803E6FD8;
        state->rollCooldownInit = lbl_803E6FDC;
        state->rollEnergyMax = lbl_803E6FE0;
        state->altRollEnergyMax = lbl_803E6F2C;
        state->rollEnergy = state->rollEnergyMax;
        state->altRollEnergy = state->altRollEnergyMax;
        state->wingFlexCur = (c6F5C = lbl_803E6F5C);
        state->wingFlexTarget = c6F5C;
        if ((obj)->anim.mapEventSlot == 0x26)
        {
            state->velZ = 0.0f;
        }
        else
        {
            state->velZ = c6F78;
        }
        *(s16*)&state->projLifetime = 0x28;
        state->projSpeed = lbl_803E6FE0;
        *(s16*)&state->fireDelay = 0x6;
        state->bombProjectileParam = 0x5a;
        state->bombProjectileLifetime = lbl_803E6F34;
        state->bombFireDelay = 0xc;
        state->maxBombCount = 0x3;
        state->wingVec[0] = objModelGetVecFn_800395d8(obj, 0);
        state->wingVec[1] = objModelGetVecFn_800395d8(obj, 1);
        state->wingVec[2] = objModelGetVecFn_800395d8(obj, 2);
        state->wingVec[3] = objModelGetVecFn_800395d8(obj, 3);
        state->wingFlexScale = lbl_803E6F64;
        *(s16*)&state->enginePitch = 0xaf;
        state->maxHealth = *(u8*)(mev + 0x1);
        state->health = state->maxHealth;
        state->bobSpeedThreshold = lbl_803E6EF8;
        state->bobRotZRate = (c6EF0 = lbl_803E6EF0);
        state->bobRotZAmp = lbl_803E6FE4;
        state->bobXRate = lbl_803E6EF4;
        state->bobXAmp = lbl_803E6FD4;
        state->bobYRate = lbl_803E6FE8;
        state->bobYAmp = lbl_803E6F80;
        state->bobBlendRate = lbl_803E6FA4;
        state->homeX = (obj)->anim.localPosX;
        state->homeY = (obj)->anim.localPosY;
        state->homeZ = (obj)->anim.localPosZ;
        state->flightHalfWidth = lbl_803E6FEC;
        state->flightUpperHeight = lbl_803E6FF0;
        state->flightLowerHeight = c6EF0;
    }
}

void arwarwing_resetFlightState(GameObject* obj)
{
    ArwingState* state = obj->extra;
    f32 v7c;
    f32 v74;
    f32 v78;

    state->maxSpeedX = lbl_803E6F70;
    state->accelX = v74 = lbl_803E6F74;
    state->maxSpeedY = v78 = lbl_803E6F78;
    state->accelY = v7c = lbl_803E6F7C;
    state->maxSpeedZ = v78;
    state->accelZ = v7c;
    state->maxAccelZ = lbl_803E6F80;
    state->minAccelZ = lbl_803E6F84;
    state->speedScaleZ = 1.0f;
    state->rotXRange = lbl_803E6F88;
    state->rotXGain = v74;
    state->rotYRange = lbl_803E6F8C;
    state->rotYGain = v7c;
    state->rotZRange = lbl_803E6F90;
    state->rotZGain = lbl_803E6F94;
    state->rotZTrimRange = lbl_803E6F98;
    state->rotZTrimGain = lbl_803E6F9C;
    state->rotZBlendThreshold = lbl_803E6FA0;
    state->rotZBlendRate = lbl_803E6FA4;
    state->barrelRollSpeed = lbl_803E6FA8;
    state->unk3FA = 0x19;
    state->barrelRollDecelRange = lbl_803E6FAC;
    state->rootMotionScale = lbl_803E6FB0;
    state->barrelRollMaxSpeedScale = lbl_803E6FB4;
    state->barrelRollAccelScale = lbl_803E6FB8;
    state->speedScaleRollL = lbl_803E6FBC;
    state->speedScaleRollR = lbl_803E6F64;
    state->rollEnergy = state->rollEnergyMax;
    state->altRollEnergy = state->altRollEnergyMax;
    state->wingFlexTarget = state->wingFlexCur = lbl_803E6F5C;
    state->velZ = state->velY = state->velX = 0.0f;
    state->laserLevel = 0;
    obj->anim.localPosX = state->homeX;
    obj->anim.localPosY = state->homeY;
    obj->anim.localPosZ = state->homeZ;
    state->rotYCur = 0;
    state->rotZCur = 0;
    obj->anim.rotX = 0;
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
}

void arwarwing_setFlightHalfWidth(GameObject* arwing, f32 width)
{
    (*(ArwingState**)&arwing->extra)->flightHalfWidth = width;
}

int arwarwing_getRotY(GameObject* arwing)
{
    return (s16)(*(ArwingState**)&arwing->extra)->rotYCur;
}

void arwarwing_setRotY(GameObject* arwing, int rotY)
{
    (*(ArwingState**)&arwing->extra)->rotYCur = (s16)rotY;
}

void arwarwing_getVelocity(Vec3f* out, GameObject* arwing)
{
    *out = *(Vec3f*)&(*(ArwingState**)&arwing->extra)->velX;
}

void arwarwing_setVelocity(GameObject* arwing, int velocity)
{
    ArwingState* state = arwing->extra;
    state->velX = ((ArwArwingVec3*)velocity)->x;
    state->velY = ((ArwArwingVec3*)velocity)->y;
    state->velZ = ((ArwArwingVec3*)velocity)->z;
}

void arwarwing_addVelocity(GameObject* arwing, const Vec3f* velocity)
{
    int v = (int)&((ArwingState*)arwing->extra)->velX;
    PSVECAdd((const Vec*)v, (const Vec*)velocity, (Vec*)v);
}

void arwarwing_clearActiveBomb(GameObject* arwing)
{
    (*(ArwingState**)&arwing->extra)->activeBombObj = 0;
}

int arwarwing_getRequiredRingCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->requiredRings;
}

int arwarwing_getCollectedRingCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->collectedRings;
}

void arwarwing_addScore(GameObject* arwing, u8 amount)
{
    ArwingState* state = arwing->extra;
    int clamped;
    state->score += amount;
    clamped = state->score;
    if ((u32)clamped > 0x270f)
    {
        clamped = 0x270f;
    }
    state->score = clamped;
}

int arwarwing_getScore(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    int clamped = state->score;
    if ((u32)clamped > 0x270f)
    {
        clamped = 0x270f;
    }
    state->score = clamped;
    return state->score;
}

int arwarwing_getBombCount(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->bombCount;
}

int arwarwing_getMaxHealth(GameObject* arwing)
{
    return *(s8*)&(*(ArwingState**)&arwing->extra)->maxHealth;
}

int arwarwing_getHealth(GameObject* arwing)
{
    return *(s8*)&(*(ArwingState**)&arwing->extra)->health;
}

int arwarwing_incrementPickup6DACount(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6DACount)++;
}

int arwarwing_incrementPickup6DBCount(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6DBCount)++;
}

int arwarwing_incrementPickup6D9Count(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6D9Count)++;
}

int arwarwing_incrementPickup6D8Count(GameObject* arwing)
{
    return ((*(ArwingState**)&arwing->extra)->pickup6D8Count)++;
}

int arwarwing_incrementCollectedRingCount(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    int clamped;
    if (state->collectedRings == 9)
    {
        state->score += 0x64;
        clamped = state->score;
        if ((u32)clamped > 0x270f)
        {
            clamped = 0x270f;
        }
        state->score = clamped;
    }
    return (state->collectedRings)++;
}

void arwarwing_addMaxHealth(GameObject* arwing, int amount)
{
    ArwingState* state = arwing->extra;
    *(s8*)&state->maxHealth = state->maxHealth + amount;
}

void arwarwing_addHealth(GameObject* arwing, int amount)
{
    ArwingState* state = arwing->extra;
    int clamped;

    *(s8*)&state->health = state->health + amount;
    if (*(s8*)&state->health < 0)
    {
        clamped = 0;
    }
    else
    {
        clamped = (*(s8*)&state->health > *(s8*)&state->maxHealth) ? *(s8*)&state->maxHealth : *(s8*)&state->health;
    }
    *(s8*)&state->health = clamped;
    if (*(s8*)&state->health > 3)
    {
        Sfx_StopObjectChannel((u32)arwing, 4);
    }
}

void arwarwing_addBomb(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    if (state->bombCount < state->maxBombCount)
    {
        (state->bombCount)++;
    }
}

void arwarwing_upgradeLaserLevel(GameObject* arwing)
{
    ArwingState* state = arwing->extra;
    if ((s8)state->laserLevel < 2)
    {
        (state->laserLevel)++;
    }
}

int arwarwing_isExplodingOrWarping(GameObject* arwing)
{
    int result = 0;
    u32 v = (*(ArwingState**)&arwing->extra)->mode;
    if (v == ARWING_MODE_EXPLODE || v == ARWING_MODE_WARPOUT)
    {
        result = 1;
    }
    return result;
}

int arwarwing_isBarrelRolling(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->mode == ARWING_MODE_BARRELROLL;
}

int arwarwing_isDead(GameObject* arwing)
{
    return (*(ArwingState**)&arwing->extra)->mode == ARWING_MODE_DEAD;
}

GameObject* getArwing(void)
{
    return gArwing;
}

int arwarwing_getExtraSize(void)
{
    return 0x498;
}

int arwarwing_getObjectTypeId(void)
{
    return 0;
}

void arwarwing_free(GameObject* obj)
{
    ArwingState* state = (obj)->extra;

    ObjGroup_RemoveObject((int)obj, ARWARWING_OBJGROUP);
    gArwing = NULL;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}

void arwarwing_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    ArwingState* state = (obj)->extra;
    int dx, dy;

    if (state->hitShake != 0)
    {
        dx = (int)(lbl_803E6FF4 * mathSinf(lbl_803E6EFC * (f32) * (u16*)&state->shakePitch / lbl_803E6F00));
        dy = (int)(lbl_803E6F5C * mathSinf(lbl_803E6EFC * (f32) * (u16*)&state->shakeYaw / lbl_803E6F00));
        (obj)->anim.rotY = (s16)((obj)->anim.rotY + dx);
        (obj)->anim.rotZ = (s16)((obj)->anim.rotZ + dy);
    }
    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
    if (state->hitShake != 0)
    {
        (obj)->anim.rotY = (s16)((obj)->anim.rotY - dx);
        (obj)->anim.rotZ = (s16)((obj)->anim.rotZ - dy);
    }
}

void arwarwing_hitDetect(GameObject* obj)
{
    ArwingState* state = (obj)->extra;
    f32 pos[3];
    f32 mtx[16];

    if (((obj)->objectFlags & ARWARWING_OBJFLAG_PARENT_SLACK) != 0 && state->aimSnapshotValid != 0)
    {
        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
        PSMTXMultVec((MtxP)mtx, (const Vec*)&state->aimOffsetX, (Vec*)pos);
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        {
            f32 posY = *(volatile f32*)&pos[1];
            fn_8008020C((s16)(0x8000 - (obj)->anim.rotX + state->aimYaw), (s16)((obj)->anim.rotY + state->aimPitch),
                        (s16)((obj)->anim.rotZ + state->aimRoll), pos[0], posY, pos[2], lbl_803E6FF8);
        }
    }
}

#pragma dont_inline on
void arwarwing_update(GameObject* obj)
{
    ArwingState* state = obj->extra;
    s16 camRot[3];
    f32 camPos[2];
    u8 mode;
    s16 wingRot;
    f32 timer;
    f32 throttle;
    s16* vv;

    if ((state->flags477 & ARWING_FLAG_ACTIVE) == 0)
    {
        arwarwing_initAttachments(obj, state);
        return;
    }
    mode = state->mode;
    if (mode == ARWING_MODE_EXPLODE)
    {
        timer = state->modeTimer - timeDelta;
        state->modeTimer = timer;
        if (timer <= 0.0f)
        {
            state->mode = ARWING_MODE_WARPOUT;
            (*gScreenTransitionInterface)->start(0x14, 1);
            state->modeTimer = lbl_803E6F34;
        }
        return;
    }
    if (mode == ARWING_MODE_WARPOUT)
    {
        timer = state->modeTimer - timeDelta;
        state->modeTimer = timer;
        if (timer <= 0.0f)
        {
            if ((obj)->anim.mapEventSlot == 0x26)
            {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                warpToMap(0x32, 0);
            }
            else
            {
                warpToMap(0x60, 0);
            }
        }
        return;
    }
    if (mode == ARWING_MODE_DEAD)
    {
        timer = state->modeTimer - timeDelta;
        state->modeTimer = timer;
        if (timer <= 0.0f)
        {
            state->mode = ARWING_MODE_EXPLODE;
            state->modeTimer = gArwingExplodeModeTime;
            (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            spawnExplosionLegacy((int)obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        state->rotZCur = (int)(lbl_803E6F6C * timeDelta + (f32)state->rotZCur);
        (obj)->anim.rotZ = (s16)state->rotZCur;
        state->velY = state->velY - lbl_803E6EF8 * timeDelta;
        objMove((GameObject*)obj, state->velX * timeDelta, state->velY * timeDelta,
                state->velZ * timeDelta);
        arwarwing_clampToFlightBounds(obj, state);
        state->thrusterL->anim.flags |= OBJANIM_FLAG_HIDDEN;
        state->thrusterR->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        arwarwing_readControls(obj, state);
        if (((obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        {
            *(s16*)&state->inputFlags2 = 0;
            *(s16*)&state->inputFlags = 0;
            state->thrusterL->anim.flags |= OBJANIM_FLAG_HIDDEN;
            state->thrusterR->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        else
        {
            state->thrusterL->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            throttle = lbl_803E6FFC * timeDelta + (f32)(u32)state->thrusterL->anim.alpha;
            if (throttle > lbl_803E7000)
                throttle = lbl_803E7000;
            state->thrusterL->anim.alpha = throttle;
            state->thrusterR->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            state->thrusterR->anim.alpha = throttle;
        }
        state->velTargetX = -state->stickX * state->maxSpeedX;
        state->velTargetY = -state->stickY * state->maxSpeedY;
        state->velTargetZ = state->maxSpeedZ * state->speedScaleZ;
        state->rotXTarget = (int)(-state->stickX * state->rotXRange);
        state->rotYTarget = (int)(state->stickY * state->rotYRange);
        state->rotZTarget = (int)(state->stickX * state->rotZRange);
        state->rotZTrimTarget =
            (int)(state->rotZTrimRange *
                  (state->lTriggerTrim + state->rTriggerTrim));
        arwarwing_updateFlightPhysics(obj, state);
        arwarwing_updateWeaponFire(obj, state);
        arwarwing_updateBombFire(obj, state);

        state->wingVec[0][0] = (s16)((f32)(-state->rotZCur) * state->wingFlexScale);
        state->wingVec[0][2] = (s16)((f32)state->rotZCur * state->wingFlexScale);
        state->wingVec[1][0] = (s16)((f32)(-state->rotZCur) * state->wingFlexScale);
        state->wingVec[1][2] = (s16)((f32)state->rotZCur * state->wingFlexScale);
        wingRot = (s16)((f32)state->rotZCur * state->wingFlexScale);
        state->wingVec[2][2] = wingRot;
        state->wingVec[2][0] = wingRot;
        wingRot = (s16)((f32)state->rotZCur * state->wingFlexScale);
        state->wingVec[3][2] = wingRot;
        state->wingVec[3][0] = wingRot;

        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)state->wingVec[0][0]);
        state->wingVec[0][0] = wingRot;
        wingRot = (s16)((f32)state->rotYCur * state->wingFlexScale +
                        (f32)state->wingVec[0][2]);
        state->wingVec[0][2] = wingRot;
        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)state->wingVec[1][0]);
        state->wingVec[1][0] = wingRot;
        wingRot = (s16)((f32)state->rotYCur * state->wingFlexScale +
                        (f32)state->wingVec[1][2]);
        state->wingVec[1][2] = wingRot;
        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)state->wingVec[2][0]);
        state->wingVec[2][0] = wingRot;
        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)state->wingVec[2][2]);
        state->wingVec[2][2] = wingRot;
        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)state->wingVec[3][0]);
        state->wingVec[3][0] = wingRot;
        wingRot = (s16)((f32)(-state->rotYCur) * state->wingFlexScale +
                        (f32)(vv = state->wingVec[3])[2]);
        vv[2] = wingRot;
    }

    arwarwing_updateRollAndEngine((int)obj, state);
    (*gCameraInterface)->releaseAction(state->camPos, 0xc);
    camRot[0] = (obj)->anim.rotX;
    camRot[1] = (obj)->anim.rotY;
    camRot[2] = (s16)state->rotZCur;
    (*gCameraInterface)->releaseAction(camRot, 6);
    camPos[0] = state->maxSpeedZ;
    camPos[1] = state->velZ;
    (*gCameraInterface)->releaseAction(camPos, 8);
    arwarwing_handlePathDamage(obj, state);
    arwarwing_handleObjectDamage(obj, state);
    arwarwing_emitDamageEffects((int)obj, state);
}
#pragma dont_inline off

void arwarwing_init(GameObject* obj)
{
    ArwingState* state;
    u8* pathBlock;
    ArwInitCfg cfg;

    *(ArwInitCfgAB*)&cfg = *(ArwInitCfgAB*)&gArwingInitConfig;
    cfg.c = gArwingInitConfig.c;
    state = obj->extra;
    pathBlock = state->pathBlock;
    (obj)->animEventCallback = arwarwing_SeqFn;
    (*gPathControlInterface)->init(pathBlock, 4, 0x1040006, 1);
    (*gPathControlInterface)->setup(pathBlock, 3, gArwingPathSetupData, sArwingPathName, &cfg);
    (*gPathControlInterface)->attachObject((void*)obj, pathBlock);
    ObjGroup_AddObject((int)obj, ARWARWING_OBJGROUP);
    gArwing = obj;
    ObjHits_SetTargetMask((int)obj, 1);
    state->fullLoadout = 1;
    switch ((obj)->anim.mapEventSlot - 0x26)
    {
    case 27:
    default:
        state->fullLoadout = 0;
        break;
    case 20:
        state->levelIndex = 0;
        state->requiredRings = 1;
        state->scoreSlot = 0;
        break;
    case 21:
        state->levelIndex = 1;
        state->requiredRings = 3;
        state->scoreSlot = 1;
        break;
    case 23:
        state->levelIndex = 2;
        state->requiredRings = 7;
        state->scoreSlot = 3;
        break;
    case 22:
        state->levelIndex = 3;
        state->requiredRings = 5;
        state->scoreSlot = 2;
        break;
    case 24:
        state->levelIndex = 4;
        state->requiredRings = 0xa;
        state->scoreSlot = 4;
        break;
    case 0:
        break;
    }
}

void arwarwing_release(void)
{
}

void arwarwing_initialise(void)
{
}
