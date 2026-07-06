/*
 * Firefly orbit-record helpers (compiled just ahead of dll_020B_firefly).
 *
 * A LgtFireFlyRec drives one firefly's hovering motion. fn_801F4C28 seeds the
 * record from the object's spawn position - the four src slots and pos all
 * start at the object's local position - and picks a random initial angle and
 * per-frame angular step plus the orbit radius bounds. fn_801F4D54 advances the
 * record one frame: it re-rolls the vertical bob (offY) and outward radius
 * (offZ), spins the orbit angle and rotates a unit offset by it through
 * vecRotateZXY, then re-bases the resulting offset onto pos. fn_801F4C04 is the
 * object think callback, forwarding to the firefly update in dll_020B_firefly.
 */
#include "main/dll/LGT/lgtcontrollightrec_struct.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EB4;
extern f32 lbl_803E5EB8;
extern f32 lbl_803E5EBC;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;
extern void FireFlyFn_801f4f88(int* obj);

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

int fn_801F4C04(int* obj)
{
    FireFlyFn_801f4f88(obj);
    return 0;
}

void fn_801F4C28(u8* obj, u8* rec)
{
    ((LgtFireFlyRec*)rec)->src0X = ((GameObject*)obj)->anim.localPosX;
    ((LgtFireFlyRec*)rec)->src0Y = ((GameObject*)obj)->anim.localPosY;
    ((LgtFireFlyRec*)rec)->src0Z = ((GameObject*)obj)->anim.localPosZ;
    ((LgtFireFlyRec*)rec)->src1X = ((GameObject*)obj)->anim.localPosX;
    ((LgtFireFlyRec*)rec)->src1Y = ((GameObject*)obj)->anim.localPosY;
    ((LgtFireFlyRec*)rec)->src1Z = ((GameObject*)obj)->anim.localPosZ;
    ((LgtFireFlyRec*)rec)->src2X = ((GameObject*)obj)->anim.localPosX;
    ((LgtFireFlyRec*)rec)->src2Y = ((GameObject*)obj)->anim.localPosY;
    ((LgtFireFlyRec*)rec)->src2Z = ((GameObject*)obj)->anim.localPosZ;
    ((LgtFireFlyRec*)rec)->src3X = ((GameObject*)obj)->anim.localPosX;
    ((LgtFireFlyRec*)rec)->src3Y = ((GameObject*)obj)->anim.localPosY;
    ((LgtFireFlyRec*)rec)->src3Z = ((GameObject*)obj)->anim.localPosZ;
    ((LgtFireFlyRec*)rec)->baseX = lbl_803E5EAC;
    ((LgtFireFlyRec*)rec)->baseY = lbl_803E5EB0;
    ((LgtFireFlyRec*)rec)->baseZ = lbl_803E5EB4;
    ((LgtFireFlyRec*)rec)->unk68 = 0;
    ((LgtFireFlyRec*)rec)->unk67 = 0;
    ((LgtFireFlyRec*)rec)->angleStep =
        randomGetRange(FIREFLY_ANGLE_STEP_MIN, FIREFLY_ANGLE_STEP_MAX);
    ((LgtFireFlyRec*)rec)->angle = randomGetRange(0, FIREFLY_ANGLE_INIT_MAX);
    ((LgtFireFlyRec*)rec)->ampMax = FIREFLY_AMP_MAX;
    ((LgtFireFlyRec*)rec)->unk66 = 4;
    ((LgtFireFlyRec*)rec)->radiusMin = lbl_803E5EB8;
    ((LgtFireFlyRec*)rec)->radius = lbl_803E5EBC;
    ((LgtFireFlyRec*)rec)->posX = ((GameObject*)obj)->anim.localPosX;
    ((LgtFireFlyRec*)rec)->posY = ((GameObject*)obj)->anim.localPosY;
    ((LgtFireFlyRec*)rec)->posZ = ((GameObject*)obj)->anim.localPosZ;
    ((LgtFireFlyRec*)rec)->firstFrame = 1;
    ((LgtFireFlyRec*)rec)->unk78 = lbl_803E5EC0;
}

void fn_801F4D54(int obj, u8* rec)
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

    ((LgtFireFlyRec*)rec)->offX = lbl_803E5EC4;
    if (((LgtFireFlyRec*)rec)->firstFrame != 0)
    {
        ((LgtFireFlyRec*)rec)->offY = (f32)(s32)(((LgtFireFlyRec*)rec)->ampMax);
        ((LgtFireFlyRec*)rec)->firstFrame = 0;
    }
    else
    {
        ((LgtFireFlyRec*)rec)->offY =
            (f32)(s32)(randomGetRange(0, ((LgtFireFlyRec*)rec)->ampMax));
    }
    if (((LgtFireFlyRec*)rec)->radius < lbl_803E5EC8)
    {
        ((LgtFireFlyRec*)rec)->offZ = lbl_803E5EC4;
    }
    else
    {
        ((LgtFireFlyRec*)rec)->offZ =
            ((LgtFireFlyRec*)rec)->radius -
            (f32)(s32)(randomGetRange(FIREFLY_RADIUS_MARGIN,
                                      (s16)(s32)((LgtFireFlyRec*)rec)->radius));
    }
    ((LgtFireFlyRec*)rec)->angle +=
        (s16)randomGetRange(FIREFLY_ANGLE_ADVANCE_MIN, FIREFLY_ANGLE_ADVANCE_MAX);
    rot.scratch1 = lbl_803E5EC4;
    rot.scratch2 = lbl_803E5EC4;
    rot.scratch3 = lbl_803E5EC4;
    rot.scratch0 = lbl_803E5EB4;
    rot.rotY = 0;
    rot.rotX = 0;
    rot.rotZ = ((LgtFireFlyRec*)rec)->angle;
    vecRotateZXY(&rot, rec + 0x34);
    ((LgtFireFlyRec*)rec)->offX =
        ((LgtFireFlyRec*)rec)->offX + ((LgtFireFlyRec*)rec)->posX;
    ((LgtFireFlyRec*)rec)->offY =
        ((LgtFireFlyRec*)rec)->offY + ((LgtFireFlyRec*)rec)->posY;
    ((LgtFireFlyRec*)rec)->offZ =
        ((LgtFireFlyRec*)rec)->offZ + ((LgtFireFlyRec*)rec)->posZ;
}
