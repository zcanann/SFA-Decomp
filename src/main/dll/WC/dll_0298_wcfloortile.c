/*
 * wcfloortile (DLL 0x298) - a collapsing floor tile in the Walled City
 * (WC). The tile sits flush until armed: once its arm game bit is set it
 * watches its map block's hit entries for a triggering entry, then enters a
 * shake-and-fall phase (jittering rotY/rotZ, accelerating down velocityY)
 * while fading alpha toward zero with the drop distance. state->phase: 0
 * idle/armed-watch, 1 shaking/falling/fading, 2 fallen (alpha 0, collision
 * off), 3 restored (a second game bit snaps the tile back to its placement
 * Y, fades alpha back in and re-enables collision). On each phase change it
 * reports to the level controller. state->flags: 1|2 bookkeeping, 4 armed.
 *
 * NOTE: this object's TU text range (0x8022A298-0x8022B998) also contains
 * the arwarwing_* Arwing flight helpers (readControls, updateFlightPhysics,
 * updateBombFire, spawnBomb, updateThrusters, updateBarrelRoll,
 * clampToFlightBounds). They are compiled into this object in retail and
 * are called from the Arwing DLL (dll_029A_arwarwing); they are not part of
 * the floor tile and must not be moved or removed.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/track_dolphin_api.h"
#include "dolphin/mtx.h"
#include "main/dll/WC/dll_0298_wcfloortile.h"
#include "main/debug.h"
#include "main/object.h"
#include "main/game_object.h"
#include "main/dll/ARW/arwing_state.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/ARW/dll_029C_arwarwingbo.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define WCFLOORTILE_CHILD_OBJ_BOMB 0x605

#define PAD_TRIGGER_Z 0x20
#define PAD_TRIGGER_R 0x40
#define PAD_BUTTON_B  0x200

int wcfloortile_getExtraSize(void)
{
    return 8;
}

int wcfloortile_getObjectTypeId(void)
{
    return 0;
}

void wcfloortile_free(void)
{
}

void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E98);
    }
}

void wcfloortile_hitDetect(void)
{
}

void wcfloortile_init(GameObject* obj)
{
    WcFloorTileState* state = obj->extra;

    obj->anim.rotX = -0x4000;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= 0x1800;
    state->flags |= 2;
}

void wcfloortile_release(void)
{
}

void wcfloortile_initialise(void)
{
}

void wcfloortile_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    WcFloorTileState* state = ((GameObject*)obj)->extra;
    int off;
    int i;
    WcFloorTileSetup* setup = (WcFloorTileSetup*)((GameObject*)obj)->anim.placementData;

    if ((u32)mainGetBit(824) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY;
        state->phase = WCFLOORTILE_PHASE_RESTORE;
    }
    switch (state->phase)
    {
    case WCFLOORTILE_PHASE_IDLE:
    default:
        if (state->flags & 4)
        {
            if (0 < *(s8*)(*(int*)(obj + 0x58) + 0x10f))
            {
                f32 z = 0.0f;
                for (i = 0, off = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); off += 4, i++)
                {
                    GameObject* e = *(GameObject**)(*(int*)(obj + 0x58) + off + 0x100);
                    if (e->anim.classId == 1)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c6);
                        state->phase = WCFLOORTILE_PHASE_FALLING;
                        state->shakeTime = z;
                        ((GameObject*)obj)->anim.velocityY = z;
                    }
                }
            }
        }
        else if ((u32)mainGetBit(613) != 0)
        {
            state->flags |= 4;
        }
        break;
    case WCFLOORTILE_PHASE_FALLING:
        state->shakeTime = state->shakeTime + timeDelta;
        if (state->shakeTime > 120.0f)
        {
            state->flags |= 3;
            state->shakeTime = 120.0f;
            ((GameObject*)obj)->anim.velocityY = lbl_803E6EA4 * timeDelta + ((GameObject*)obj)->anim.velocityY;
        }
        state->shakeMag = lbl_803E6EA8 * (state->shakeTime / 120.0f);
        ((GameObject*)obj)->anim.rotY = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.rotZ = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.localPosY =
            ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
        {
            f32 d = setup->base.posY - ((GameObject*)obj)->anim.localPosY;
            f32 alpha;
            if (d < lbl_803E6EAC)
            {
                alpha = lbl_803E6EB0;
            }
            else if (d > lbl_803E6EB4)
            {
                alpha = lbl_803E6E9C;
            }
            else
            {
                alpha = (d - lbl_803E6EAC) / lbl_803E6EB8;
                alpha = lbl_803E6E98 - alpha;
                if (alpha > lbl_803E6E98)
                {
                    alpha = lbl_803E6E98;
                }
                else if (alpha < lbl_803E6E9C)
                {
                    alpha = lbl_803E6E9C;
                }
                alpha = alpha * lbl_803E6EB0;
            }
            objAnim->alpha = (u8)(int)alpha;
        }
        if (objAnim->alpha == 0)
        {
            state->phase = WCFLOORTILE_PHASE_FALLEN;
        }
        break;
    case WCFLOORTILE_PHASE_FALLEN:
        objAnim->alpha = 0;
        ObjHits_DisableObject(obj);
        state->flags |= 3;
        break;
    case WCFLOORTILE_PHASE_RESTORE:
    {
        f32 a = (f32)(u32)objAnim->alpha;
        a = lbl_803E6EBC * timeDelta + a;
        if (a > lbl_803E6EB0)
        {
            a = lbl_803E6EB0;
        }
        objAnim->alpha = a;
    }
        ObjHits_EnableObject(obj);
        break;
    }
    {
        setup = (WcFloorTileSetup*)((GameObject*)obj)->anim.placementData;
        if (fn_80065640() != 0)
        {
            state->flags |= 2;
        }
        if (state->flags & 2)
        {
            if (fn_80065640() == 0)
            {
                fn_80065574(setup->eventId, (GameObject*)(*(int*)&((GameObject*)obj)->anim.parent), state->flags & 1);
                state->flags &= ~2;
            }
        }
    }
}

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
        arwing->velX = lbl_803E6ECC;
    }
    else if (obj->anim.localPosX < lx)
    {
        obj->anim.localPosX = lx;
        arwing->velX = lbl_803E6ECC;
    }
    if (obj->anim.localPosY > hy)
    {
        obj->anim.localPosY = hy;
        arwing->velY = lbl_803E6ECC;
    }
    else if (obj->anim.localPosY < ly)
    {
        obj->anim.localPosY = ly;
        arwing->velY = lbl_803E6ECC;
    }
    arwing->camPos[0] = obj->anim.localPosX - arwing->homeX;
    arwing->camPos[1] = obj->anim.localPosY - arwing->homeY;
    arwing->camPos[2] = lbl_803E6ECC;
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
        arwing->velTargetZ = lbl_803E6ECC;
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
    if (arwing->rotZBlend < lbl_803E6ECC)
    {
        arwing->rotZBlend = lbl_803E6ECC;
    }
    else if (arwing->rotZBlend > lbl_803E6ED0)
    {
        arwing->rotZBlend = lbl_803E6ED0;
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
    if (arwing->bobBlend < lbl_803E6ECC)
    {
        arwing->bobBlend = lbl_803E6ECC;
    }
    else if (arwing->bobBlend > lbl_803E6ED0)
    {
        arwing->bobBlend = lbl_803E6ED0;
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

void arwarwing_updateBombFire(GameObject* obj, ArwingState* state)
{
    ArwingState* arwing = state;
    if (arwing->activeBombObj != NULL)
        return;
    {
        f32 t = arwing->bombCooldown;
        f32 zero = lbl_803E6ECC;
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
    setup = (ArwingBombSetup*)Obj_AllocObjectSetup(0x20, WCFLOORTILE_CHILD_OBJ_BOMB);
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
    src.scale = lbl_803E6ED0;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(
        mtx, lbl_803E6ECC, *(f32*)&lbl_803E6ECC, lbl_803E6EF0, &state->thrusterL->anim.localPosX,
        &state->thrusterL->anim.localPosY, &state->thrusterL->anim.localPosZ);
    state->thrusterL->anim.worldPosX = state->thrusterL->anim.localPosX;
    state->thrusterL->anim.worldPosY = state->thrusterL->anim.localPosY;
    state->thrusterL->anim.worldPosZ = state->thrusterL->anim.localPosZ;
    state->thrusterL->anim.rotZ = -slot->roll;
    state->thrusterL->anim.rotY = -slot->pitch;
    state->thrusterL->anim.rotX = 0x8000 - slot->yaw;

    Matrix_TransformPoint(
        mtx, lbl_803E6ECC, *(f32*)&lbl_803E6ECC, lbl_803E6EF4, &state->thrusterR->anim.localPosX,
        &state->thrusterR->anim.localPosY, &state->thrusterR->anim.localPosZ);
    state->thrusterR->anim.worldPosX = state->thrusterR->anim.localPosX;
    state->thrusterR->anim.worldPosY = state->thrusterR->anim.localPosY;
    state->thrusterR->anim.worldPosZ = state->thrusterR->anim.localPosZ;
    state->thrusterR->anim.rotZ = -slot->roll;
    state->thrusterR->anim.rotY = -slot->pitch;
    state->thrusterR->anim.rotX = 0x8000 - slot->yaw;
}

/* the shared header leaves dont_inline stuck on; clamps must inline to match */
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
    return -(f32)(u32)(u8)padGetLTrigger(0) / lbl_803E6ED4;
}

void arwarwing_readControls(GameObject* obj, ArwingState* state)
{
    ArwingState* aw = state;
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    aw->stickX = (f32)(s8)padGetStickX(0) / lbl_803E6EC8;
    aw->stickY = (f32)(s8)padGetStickY(0) / lbl_803E6EC8;
    if (aw->damageFlashTimer > lbl_803E6ECC)
    {
        f32 zero = lbl_803E6ECC;
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
            aw->stickX = aw->stickX * (inv = lbl_803E6ED0 - tv) + nx * tv;
            aw->stickY = aw->stickY * inv + ny * tv;
        }
    }
    aw->rTriggerTrim = (f32)(u8)padGetRTrigger(0) / lbl_803E6ED4;
    aw->rTriggerTrim = clampPos(aw->rTriggerTrim, 0.0f, 1.0f);
    aw->lTriggerTrim = -(f32)(u8)padGetLTrigger(0) / lbl_803E6ED4;
    aw->lTriggerTrim = clampNeg(aw->lTriggerTrim, -1.0f, 0.0f);
    aw->inputFlags = getButtonsJustPressed(0);
    aw->inputFlagsPrev = getButtonsJustPressedIfNotBusy(0);
    aw->inputFlags2 = getButtonsHeld(0);
    if (aw->mode == 0)
    {
        btn = aw->inputFlags;
        if ((btn & PAD_TRIGGER_Z) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_arwingflyby);
            aw->mode = 1;
            aw->barrelRollAngle = (obj)->anim.rotZ;
            aw->barrelRollDirection = aw->barrelRollSpeed;
            aw->barrelRollSpeedScale = lbl_803E6ED0;
            aw->maxSpeedX = aw->maxSpeedX * aw->barrelRollMaxSpeedScale;
            aw->accelX = aw->accelX * aw->barrelRollAccelScale;
            arwarwingbo_setActiveVisible((GameObject*)(aw->bombObj), 1, 0);
        }
        else if ((btn & PAD_TRIGGER_R) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_arwingflyby);
            aw->mode = 1;
            aw->barrelRollAngle = (obj)->anim.rotZ;
            aw->barrelRollDirection = -aw->barrelRollSpeed;
            aw->barrelRollSpeedScale = lbl_803E6ED0;
            aw->maxSpeedX = aw->maxSpeedX * aw->barrelRollMaxSpeedScale;
            aw->accelX = aw->accelX * aw->barrelRollAccelScale;
            arwarwingbo_setActiveVisible((GameObject*)(aw->bombObj), 1, 1);
        }
    }
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
    zero = lbl_803E6ECC;
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
                else if (state->barrelRollSpeedScale > lbl_803E6ED0)
                    state->barrelRollSpeedScale = lbl_803E6ED0;
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
                else if (state->barrelRollSpeedScale > lbl_803E6ED0)
                    state->barrelRollSpeedScale = lbl_803E6ED0;
            }
        }
    }
}
#pragma opt_propagation reset
