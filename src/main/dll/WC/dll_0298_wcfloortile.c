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
#include "main/game_object.h"
#include "main/dll/ARW/arwing_state.h"
#include "main/audio/sfx_ids.h"

typedef struct WcFloorTileState
{
    f32 shakeTime;
    s16 shakeMag;
    u8 phase; /* 0x6 */
    u8 flags; /* 0x7: 1|2 done, 4 armed */
} WcFloorTileState;

typedef enum WcFloorTilePhase
{
    WCFLOORTILE_PHASE_IDLE = 0,    /* armed-watch: waits for a triggering hit entry */
    WCFLOORTILE_PHASE_FALLING = 1, /* shaking, accelerating down, fading alpha out */
    WCFLOORTILE_PHASE_FALLEN = 2,  /* alpha 0, collision disabled */
    WCFLOORTILE_PHASE_RESTORE = 3, /* snapped back to Y, fading alpha in, collision on */
} WcFloorTilePhase;

typedef struct WcFloorTileSetup
{
    ObjPlacement base;
    u8 pad18[0x1A - 0x18];
    s16 eventId;
    u8 pad1C[0x24 - 0x1C];
} WcFloorTileSetup;

STATIC_ASSERT(sizeof(WcFloorTileState) == 0x8);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeTime) == 0x00);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeMag) == 0x04);
STATIC_ASSERT(offsetof(WcFloorTileState, phase) == 0x06);
STATIC_ASSERT(offsetof(WcFloorTileState, flags) == 0x07);

STATIC_ASSERT(sizeof(WcFloorTileSetup) == 0x24);
STATIC_ASSERT(offsetof(WcFloorTileSetup, base.posY) == 0x0C);
STATIC_ASSERT(offsetof(WcFloorTileSetup, eventId) == 0x1A);

int wcfloortile_getExtraSize(void) { return 8; }

int wcfloortile_getObjectTypeId(void) { return 0; }

void wcfloortile_free(void)
{
}

void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E98);
    }
}

void wcfloortile_hitDetect(void)
{
}

void wcfloortile_init(int obj)
{
    WcFloorTileState* state = ((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.rotX = -0x4000;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= 0x1800;
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
    WcFloorTileSetup* setup = (WcFloorTileSetup*)((GameObject*)obj)->anim.placementData;
    f32 shakeMax;

    if ((u32)GameBit_Get(824) != 0)
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
            int off, i;
            if (0 < *(s8*)(*(int*)(obj + 0x58) + 0x10f))
            {
                f32 z = lbl_803E6E9C;
                for (i = 0, off = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); off += 4, i++)
                {
                    int e = *(int*)(*(int*)(obj + 0x58) + off + 0x100);
                    if (*(s16*)(e + 0x44) == 1)
                    {
                        Sfx_PlayFromObject(obj, SFXsc_strafe_active);
                        state->phase = WCFLOORTILE_PHASE_FALLING;
                        state->shakeTime = z;
                        ((GameObject*)obj)->anim.velocityY = z;
                    }
                }
            }
        }
        else if ((u32)GameBit_Get(613) != 0)
        {
            state->flags |= 4;
        }
        break;
    case WCFLOORTILE_PHASE_FALLING:
        state->shakeTime = state->shakeTime + timeDelta;
        if (state->shakeTime > (shakeMax = lbl_803E6EA0))
        {
            state->flags |= 3;
            state->shakeTime = shakeMax;
            ((GameObject*)obj)->anim.velocityY = lbl_803E6EA4 * timeDelta + ((GameObject*)obj)->anim.velocityY;
        }
        state->shakeMag = lbl_803E6EA8 * (state->shakeTime / lbl_803E6EA0);
        ((GameObject*)obj)->anim.rotY = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.rotZ = randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        {
            f32 d = setup->base.posY - ((GameObject*)obj)->anim.localPosY;
            f32 t;
            if (d < lbl_803E6EAC)
            {
                t = lbl_803E6EB0;
            }
            else if (d > lbl_803E6EB4)
            {
                t = lbl_803E6E9C;
            }
            else
            {
                t = (d - lbl_803E6EAC) / lbl_803E6EB8;
                t = lbl_803E6E98 - t;
                if (t > lbl_803E6E98)
                {
                    t = lbl_803E6E98;
                }
                else if (t < lbl_803E6E9C)
                {
                    t = lbl_803E6E9C;
                }
                t = t * lbl_803E6EB0;
            }
            objAnim->alpha = (u8)(int)t;
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
                fn_80065574(setup->eventId, *(int*)&((GameObject*)obj)->anim.parent, state->flags & 1);
                state->flags &= ~2;
            }
        }
    }
}

void arwarwing_clampToFlightBounds(int obj, int state)
{
    ArwingState* arwing = (ArwingState*)state;
    f32 hy;
    f32 lx;
    f32 hx;
    f32 ly;
    hx = arwing->homeX + arwing->flightHalfWidth;
    lx = arwing->homeX - arwing->flightHalfWidth;
    hy = arwing->homeY + arwing->flightUpperHeight;
    ly = arwing->homeY - arwing->flightLowerHeight;
    if (((GameObject*)obj)->anim.localPosX > hx)
    {
        ((GameObject*)obj)->anim.localPosX = hx;
        arwing->velX = lbl_803E6ECC;
    }
    else if (((GameObject*)obj)->anim.localPosX < lx)
    {
        ((GameObject*)obj)->anim.localPosX = lx;
        arwing->velX = lbl_803E6ECC;
    }
    if (((GameObject*)obj)->anim.localPosY > hy)
    {
        ((GameObject*)obj)->anim.localPosY = hy;
        arwing->velY = lbl_803E6ECC;
    }
    else if (((GameObject*)obj)->anim.localPosY < ly)
    {
        ((GameObject*)obj)->anim.localPosY = ly;
        arwing->velY = lbl_803E6ECC;
    }
    arwing->camPos[0] = ((GameObject*)obj)->anim.localPosX - arwing->homeX;
    arwing->camPos[1] = ((GameObject*)obj)->anim.localPosY - arwing->homeY;
    arwing->camPos[2] = lbl_803E6ECC;
}

void arwarwing_updateFlightPhysics(int obj, int state)
{
    ArwingState* arwing = (ArwingState*)state;
    f32 v[3];
    f32 cz;
    int diff;
    int iv;

    if (((GameObject*)obj)->anim.mapEventSlot == 0x26)
    {
        arwing->velTargetZ = lbl_803E6ECC;
    }
    PSVECSubtract((void*)&arwing->velTargetX, &arwing->velX, v);
    v[0] = v[0] * arwing->accelX;
    v[1] = v[1] * arwing->accelY;
    v[2] = v[2] * arwing->accelZ;
    v[2] = v[2] < arwing->minAccelZ
               ? arwing->minAccelZ
               : (v[2] > arwing->maxAccelZ ? arwing->maxAccelZ : v[2]);
    PSVECScale(v, v, timeDelta);
    PSVECAdd((int)&arwing->velX, (int)v, (int)&arwing->velX);
    objMove(obj, arwing->velX * timeDelta, arwing->velY * timeDelta,
            arwing->velZ * timeDelta);

    diff = arwing->rotXTarget - (u16)arwing->rotXCur;
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * arwing->rotXGain) - arwing->rotXRate);
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    arwing->rotXRate = (int)((f32)iv * timeDelta + (f32)((ArwingState*)arwing)->rotXRate);
    arwing->rotXCur =
        (int)((f32)arwing->rotXRate * timeDelta + arwing->rotXCur);

    diff = arwing->rotYTarget - (u16)arwing->rotYCur;
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * arwing->rotYGain) - arwing->rotYRate);
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    arwing->rotYRate = (int)((f32)iv * timeDelta + (f32)((ArwingState*)arwing)->rotYRate);
    arwing->rotYCur =
        (int)((f32)arwing->rotYRate * timeDelta + arwing->rotYCur);

    diff = arwing->rotZTarget - (u16)arwing->rotZCur;
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)((f32)(int)((f32)diff * arwing->rotZGain) - arwing->rotZRate);
    iv = (iv < -0x64) ? -0x64 : ((iv > 0x64) ? 0x64 : iv);
    arwing->rotZRate = iv * timeDelta + ((ArwingState*)arwing)->rotZRate;
    arwing->rotZCur =
        (int)(arwing->rotZRate * timeDelta + arwing->rotZCur);

    if (arwing->mode == 0)
    {
        diff = arwing->rotZTrimTarget - (u16)arwing->rotZTrimCur;
        if (diff > 0x8000) diff -= 0xffff;
        if (diff < -0x8000) diff += 0xffff;
        arwing->rotZTrimCur =
            (int)(timeDelta * ((f32)diff * arwing->rotZTrimGain) + (f32)((ArwingState*)arwing)->rotZTrimCur);
        if ((f32)arwing->rotZTrimCur > arwing->rotZBlendThreshold ||
            arwing->rotZTrimCur < -arwing->rotZBlendThreshold)
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

    ((GameObject*)obj)->anim.rotX = arwing->rotXCur;
    ((GameObject*)obj)->anim.rotY = arwing->rotYCur;
    if (arwing->mode == 1)
    {
        arwarwing_updateBarrelRoll(obj, state);
    }
    else
    {
        ((GameObject*)obj)->anim.rotZ = ((f32)arwing->rotZCur * arwing->rotZBlend +
            arwing->rotZTrimCur);
        if (((GameObject*)obj)->anim.rotZ < -0x4000)
        {
            ((GameObject*)obj)->anim.rotZ = -0x4000;
        }
        else if (((GameObject*)obj)->anim.rotZ > 0x4000)
        {
            ((GameObject*)obj)->anim.rotZ = 0x4000;
        }
    }

    if (sqrtf(arwing->velX * arwing->velX +
            arwing->velY * arwing->velY) < arwing->bobSpeedThreshold &&
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

    ((GameObject*)obj)->anim.rotZ = (arwing->bobBlend *
        (arwing->bobRotZAmp *
            mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobRotZPhase /
                     lbl_803E6F00)) +
        (f32) * &((GameObject*)obj)->anim.rotZ);
    ((GameObject*)obj)->anim.localPosX =
        arwing->bobBlend *
        (arwing->bobXAmp *
            mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobXPhase / lbl_803E6F00)) +
        ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY =
        arwing->bobBlend *
        (arwing->bobYAmp *
            mathSinf(lbl_803E6EFC * (f32)(u32)arwing->bobYPhase / lbl_803E6F00)) +
        ((GameObject*)obj)->anim.localPosY;
    arwing->bobRotZPhase =
        (arwing->bobRotZRate * timeDelta + (f32)(u32)
    arwing->bobRotZPhase
    )
    ;
    arwing->bobXPhase =
        (arwing->bobXRate * timeDelta + (f32)(u32)
    arwing->bobXPhase
    )
    ;
    arwing->bobYPhase =
        (arwing->bobYRate * timeDelta + (f32)(u32)
    arwing->bobYPhase
    )
    ;
    arwarwing_clampToFlightBounds(obj, state);
}

#pragma peephole off
void arwarwing_updateBombFire(int obj, int state)
{
    ArwingState* arwing = (ArwingState*)state;
    if (*(void* *)&arwing->activeBombObj != NULL)
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
    if (arwing->inputFlags & 0x200)
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

#pragma peephole off
void arwarwing_spawnBomb(int obj, int state, int side)
{
    ArwingState* arwing = (ArwingState*)state;
    f32 pz, py, px;
    int setup;
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
    setup = Obj_AllocObjectSetup(0x20, 0x605);
    ((ObjPlacement*)setup)->posX = px;
    ((ObjPlacement*)setup)->posY = py;
    ((ObjPlacement*)setup)->posZ = pz;
    *(u8*)(setup + 0x1a) = ((GameObject*)obj)->anim.rotX >> 8;
    *(u8*)(setup + 0x19) = ((GameObject*)obj)->anim.rotY >> 8;
    *(u8*)(setup + 0x18) = ((GameObject*)obj)->anim.rotZ >> 8;
    ((ObjPlacement*)setup)->color[0] = 1;
    ((ObjPlacement*)setup)->color[1] = 1;
    arwing->activeBombObj = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
    fn_8022ED74(arwing->activeBombObj, *(u16*)&arwing->bombProjectileParam);
    fn_8022ECE0(arwing->activeBombObj, arwing->bombProjectileLifetime);
    Sfx_PlayFromObject(obj, SFXbaddie_rach_call3);
}

void arwarwing_updateThrusters(int obj, int state)
{

    int slot;
    f32 mtx[16];
    ArwProjPosSrc src;

    slot = Camera_GetCurrentViewSlot();
    src.pos[0] = ((GameObject*)obj)->anim.localPosX;
    src.pos[1] = ((GameObject*)obj)->anim.localPosY;
    src.pos[2] = ((GameObject*)obj)->anim.localPosZ;
    src.rot[0] = ((GameObject*)obj)->anim.rotX;
    src.rot[1] = ((GameObject*)obj)->anim.rotY;
    src.rot[2] = 0;
    src.scale = lbl_803E6ED0;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(mtx, lbl_803E6ECC, *(f32*)&lbl_803E6ECC, lbl_803E6EF0,
                          (f32*)(((ArwingState*)state)->thrusterL + 0xc),
                          (f32*)(((ArwingState*)state)->thrusterL + 0x10),
                          (f32*)(((ArwingState*)state)->thrusterL + 0x14));
    *(f32*)(((ArwingState*)state)->thrusterL + 0x18) = *(f32*)(((ArwingState*)state)->thrusterL + 0xc);
    *(f32*)(((ArwingState*)state)->thrusterL + 0x1c) = *(f32*)(((ArwingState*)state)->thrusterL + 0x10);
    *(f32*)(((ArwingState*)state)->thrusterL + 0x20) = *(f32*)(((ArwingState*)state)->thrusterL + 0x14);
    *(s16*)(((ArwingState*)state)->thrusterL + 4) = -*(s16*)(slot + 4);
    *(s16*)(((ArwingState*)state)->thrusterL + 2) = -*(s16*)(slot + 2);
    *(s16*)(((ArwingState*)state)->thrusterL + 0) = 0x8000 - *(s16*)slot;

    Matrix_TransformPoint(mtx, lbl_803E6ECC, *(f32*)&lbl_803E6ECC, lbl_803E6EF4,
                          (f32*)(((ArwingState*)state)->thrusterR + 0xc),
                          (f32*)(((ArwingState*)state)->thrusterR + 0x10),
                          (f32*)(((ArwingState*)state)->thrusterR + 0x14));
    *(f32*)(((ArwingState*)state)->thrusterR + 0x18) = *(f32*)(((ArwingState*)state)->thrusterR + 0xc);
    *(f32*)(((ArwingState*)state)->thrusterR + 0x1c) = *(f32*)(((ArwingState*)state)->thrusterR + 0x10);
    *(f32*)(((ArwingState*)state)->thrusterR + 0x20) = *(f32*)(((ArwingState*)state)->thrusterR + 0x14);
    *(s16*)(((ArwingState*)state)->thrusterR + 4) = -*(s16*)(slot + 4);
    *(s16*)(((ArwingState*)state)->thrusterR + 2) = -*(s16*)(slot + 2);
    *(s16*)(((ArwingState*)state)->thrusterR + 0) = 0x8000 - *(s16*)slot;
}

void arwarwing_readControls(int obj, int state)
{
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    ((ArwingState*)state)->stickX = (f32)(s8)
    padGetStickX(0) / lbl_803E6EC8;
    ((ArwingState*)state)->stickY = (f32)(s8)
    padGetStickY(0) / lbl_803E6EC8;
    if (((ArwingState*)state)->damageFlashTimer > lbl_803E6ECC)
    {
        f32 zero = lbl_803E6ECC;
        nx = -((ArwingState*)state)->knockVelX;
        ny = -((ArwingState*)state)->knockVelZ;
        ((ArwingState*)state)->damageFlashTimer = ((ArwingState*)state)->damageFlashTimer - timeDelta;
        tv = lbl_8032B4A8[(int)((ArwingState*)state)->damageFlashTimer];
        if (((ArwingState*)state)->damageFlashTimer <= zero)
        {
            ((ArwingState*)state)->hitShake = 0;
            (*gPathControlInterface)->attachObject((void*)obj, ((ArwingState*)state)->pathBlock);
        }
        {
            f32 inv;
            ((ArwingState*)state)->stickX =
                ((ArwingState*)state)->stickX * (inv = lbl_803E6ED0 - tv) + nx * tv;
            ((ArwingState*)state)->stickY =
                ((ArwingState*)state)->stickY * inv + ny * tv;
        }
    }
    ((ArwingState*)state)->rTriggerTrim = (f32)(u32)(u8)
    padGetRTrigger(0) / lbl_803E6ED4;
    {
        f32 rt = ((ArwingState*)state)->rTriggerTrim;
        ((ArwingState*)state)->rTriggerTrim =
            (rt < lbl_803E6ECC) ? lbl_803E6ECC : ((rt > lbl_803E6ED0) ? lbl_803E6ED0 : rt);
    }
    ((ArwingState*)state)->lTriggerTrim = -(f32)(u32)(u8)
    padGetLTrigger(0) / lbl_803E6ED4;
    {
        f32 lt = ((ArwingState*)state)->lTriggerTrim;
        ((ArwingState*)state)->lTriggerTrim =
            (lt < lbl_803E6ED8) ? lbl_803E6ED8 : ((lt > lbl_803E6ECC) ? lbl_803E6ECC : lt);
    }
    ((ArwingState*)state)->inputFlags = getButtonsJustPressed(0);
    ((ArwingState*)state)->inputFlagsPrev = getButtonsJustPressedIfNotBusy(0);
    ((ArwingState*)state)->inputFlags2 = getButtonsHeld(0);
    if (((ArwingState*)state)->mode == 0)
    {
        btn = ((ArwingState*)state)->inputFlags;
        if ((btn & 0x20) != 0)
        {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            ((ArwingState*)state)->mode = 1;
            ((ArwingState*)state)->barrelRollAngle = ((GameObject*)obj)->anim.rotZ;
            ((ArwingState*)state)->barrelRollDirection = ((ArwingState*)state)->barrelRollSpeed;
            ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6ED0;
            ((ArwingState*)state)->maxSpeedX = ((ArwingState*)state)->maxSpeedX * ((ArwingState*)state)->
                barrelRollMaxSpeedScale;
            ((ArwingState*)state)->accelX = ((ArwingState*)state)->accelX * ((ArwingState*)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 1, 0);
        }
        else if ((btn & 0x40) != 0)
        {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            ((ArwingState*)state)->mode = 1;
            ((ArwingState*)state)->barrelRollAngle = ((GameObject*)obj)->anim.rotZ;
            ((ArwingState*)state)->barrelRollDirection = -((ArwingState*)state)->barrelRollSpeed;
            ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6ED0;
            ((ArwingState*)state)->maxSpeedX = ((ArwingState*)state)->maxSpeedX * ((ArwingState*)state)->
                barrelRollMaxSpeedScale;
            ((ArwingState*)state)->accelX = ((ArwingState*)state)->accelX * ((ArwingState*)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 1, 1);
        }
    }
}

#pragma peephole off
void arwarwing_updateBarrelRoll(int obj, int state)
{
    f32 zero;

    ((ArwingState*)state)->barrelRollAngle =
        (int)(timeDelta * (((ArwingState*)state)->barrelRollDirection * ((ArwingState*)state)->barrelRollSpeedScale) +
            (f32)((ArwingState*)state)->barrelRollAngle);
    ((GameObject*)obj)->anim.rotZ =
        (s16)(
            timeDelta * (((ArwingState*)state)->barrelRollDirection * ((ArwingState*)state)->barrelRollSpeedScale) +
            (f32) * &((GameObject*)obj)->anim.rotZ);
    if (((ArwingState*)state)->barrelRollDirection > (zero = lbl_803E6ECC))
    {
        {
            int tgt = ((ArwingState*)state)->rotZTrimCur;
            int hi = tgt + 0xffff;
            int mid = hi - 0x7fff;
            if (((ArwingState*)state)->barrelRollAngle > hi)
            {
                ((ArwingState*)state)->mode = 0;
                ((ArwingState*)state)->rotZTrimCur = ((ArwingState*)state)->barrelRollAngle - 0xffff;
                ((ArwingState*)state)->rotZBlend = zero;
                ((ArwingState*)state)->maxSpeedX = ((ArwingState*)state)->maxSpeedX / ((ArwingState*)state)->
                    barrelRollMaxSpeedScale;
                ((ArwingState*)state)->accelX = ((ArwingState*)state)->accelX / ((ArwingState*)state)->barrelRollAccelScale;
                arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 0, 0);
            }
            else if (((ArwingState*)state)->barrelRollAngle > mid)
            {
                int d = ((ArwingState*)state)->barrelRollAngle - (u16)tgt;
                if (d > 0x8000) d -= 0xffff;
                if (d < -0x8000) d += 0xffff;
                if (d < 0) d = -d;
                ((ArwingState*)state)->barrelRollSpeedScale = d / ((ArwingState*)state)->barrelRollDecelRange;
                if (((ArwingState*)state)->barrelRollSpeedScale < lbl_803E6EF8)
                    ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6EF8;
                else if (((ArwingState*)state)->barrelRollSpeedScale > lbl_803E6ED0)
                    ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6ED0;
            }
        }
    }
    else
    {
        {
            int tgt = ((ArwingState*)state)->rotZTrimCur;
            int lo = tgt - 0xffff;
            int mid = lo + 0x7fff;
            if (((ArwingState*)state)->barrelRollAngle < lo)
            {
                ((ArwingState*)state)->mode = 0;
                ((ArwingState*)state)->rotZTrimCur = ((ArwingState*)state)->barrelRollAngle + 0xffff;
                ((ArwingState*)state)->rotZBlend = zero;
                ((ArwingState*)state)->maxSpeedX = ((ArwingState*)state)->maxSpeedX / ((ArwingState*)state)->
                    barrelRollMaxSpeedScale;
                ((ArwingState*)state)->accelX = ((ArwingState*)state)->accelX / ((ArwingState*)state)->barrelRollAccelScale;
                arwarwingbo_setActiveVisible(((ArwingState*)state)->bombObj, 0, 0);
            }
            else if (((ArwingState*)state)->barrelRollAngle > mid)
            {
                int d = ((ArwingState*)state)->barrelRollAngle - (u16)tgt;
                if (d > 0x8000) d -= 0xffff;
                if (d < -0x8000) d += 0xffff;
                if (d < 0) d = -d;
                ((ArwingState*)state)->barrelRollSpeedScale = d / ((ArwingState*)state)->barrelRollDecelRange;
                if (((ArwingState*)state)->barrelRollSpeedScale < lbl_803E6EF8)
                    ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6EF8;
                else if (((ArwingState*)state)->barrelRollSpeedScale > lbl_803E6ED0)
                    ((ArwingState*)state)->barrelRollSpeedScale = lbl_803E6ED0;
            }
        }
    }
}
