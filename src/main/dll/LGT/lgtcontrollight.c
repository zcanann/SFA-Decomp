/*
 * Firefly orbit-record helpers (compiled just ahead of dll_020B_firefly).
 *
 * A LgtFireFlyRec drives one firefly's hovering motion. fn_801F4C28 seeds the
 * record from the object's spawn position - the four src slots and pos all
 * start at the object's local position - and picks a random initial angle and
 * per-frame angular step plus the orbit radius bounds. fn_801F4D54 advances the
 * record one frame: it re-rolls the vertical bob (offY) and outward radius
 * (offZ), spins the orbit angle and rotates a unit offset by it through
 * vecRotateZXY, then re-bases the resulting offset onto pos. firefly_animEventCallback is the
 * object think callback, forwarding to the firefly update in dll_020B_firefly.
 */
#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/dll/LGT/LGTcontrollight.h"
#include "main/dll/dll_020B_firefly.h"

/* per-frame angular step bounds (1/65536-turn units) */
#define FIREFLY_ANGLE_STEP_MIN 0x1f4
#define FIREFLY_ANGLE_STEP_MAX 0x5dc
/* angle advance applied each update */
#define FIREFLY_ANGLE_ADVANCE_MIN 0xbb8
#define FIREFLY_ANGLE_ADVANCE_MAX 0x1388
/* upper bound for the random initial angle (~one full 1/65536-turn circle) */
#define FIREFLY_ANGLE_INIT_MAX 0xfde8
/* vertical bob amplitude ceiling */
#define FIREFLY_AMP_MAX 0x3c
/* minimum inward margin when re-rolling the orbit radius */
#define FIREFLY_RADIUS_MARGIN 0x14

int firefly_animEventCallback(GameObject* obj)
{
    FireFlyFn_801f4f88(obj);
    return 0;
}

void fn_801F4C28(GameObject* obj, LgtFireFlyRec* record)
{
    record->src0X = obj->anim.localPosX;
    record->src0Y = obj->anim.localPosY;
    record->src0Z = obj->anim.localPosZ;
    record->src1X = obj->anim.localPosX;
    record->src1Y = obj->anim.localPosY;
    record->src1Z = obj->anim.localPosZ;
    record->src2X = obj->anim.localPosX;
    record->src2Y = obj->anim.localPosY;
    record->src2Z = obj->anim.localPosZ;
    record->src3X = obj->anim.localPosX;
    record->src3Y = obj->anim.localPosY;
    record->src3Z = obj->anim.localPosZ;
    record->baseX = lbl_803E5EAC;
    record->baseY = lbl_803E5EB0;
    record->baseZ = lbl_803E5EB4;
    record->unk68 = 0;
    record->unk67 = 0;
    record->angleStep = randomGetRange(FIREFLY_ANGLE_STEP_MIN, FIREFLY_ANGLE_STEP_MAX);
    record->angle = randomGetRange(0, FIREFLY_ANGLE_INIT_MAX);
    record->ampMax = FIREFLY_AMP_MAX;
    record->unk66 = 4;
    record->radiusMin = lbl_803E5EB8;
    record->radius = lbl_803E5EBC;
    record->posX = obj->anim.localPosX;
    record->posY = obj->anim.localPosY;
    record->posZ = obj->anim.localPosZ;
    record->firstFrame = 1;
    record->unk78 = lbl_803E5EC0;
}

void fn_801F4D54(GameObject* obj, LgtFireFlyRec* record)
{
    struct
    {
        s16 rotZ;
        s16 rotX;
        s16 rotY;
        u8 pad0e[2];
        f32 scratch0;
        f32 scratch1;
        f32 scratch2;
        f32 scratch3;
    } rot;

    record->offX = lbl_803E5EC4;
    if (record->firstFrame != 0)
    {
        record->offY = (f32)(s32)record->ampMax;
        record->firstFrame = 0;
    }
    else
    {
        record->offY = (f32)(s32)randomGetRange(0, record->ampMax);
    }
    if (record->radius < lbl_803E5EC8)
    {
        record->offZ = lbl_803E5EC4;
    }
    else
    {
        record->offZ = record->radius -
                       (f32)(s32)randomGetRange(FIREFLY_RADIUS_MARGIN, (s16)(s32)record->radius);
    }
    record->angle += (s16)randomGetRange(FIREFLY_ANGLE_ADVANCE_MIN, FIREFLY_ANGLE_ADVANCE_MAX);
    rot.scratch1 = lbl_803E5EC4;
    rot.scratch2 = lbl_803E5EC4;
    rot.scratch3 = lbl_803E5EC4;
    rot.scratch0 = lbl_803E5EB4;
    rot.rotY = 0;
    rot.rotX = 0;
    rot.rotZ = record->angle;
    vecRotateZXY((s16*)&rot, &record->offX);
    record->offX += record->posX;
    record->offY += record->posY;
    record->offZ += record->posZ;
}
