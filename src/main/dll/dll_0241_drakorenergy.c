/*
 * drakorenergy (DLL 0x241) - the floating Krazoa-energy orb spawned during
 * the Drakor boss fight. Its extra block (DrakorEnergyState, 0xC bytes) runs
 * a small mode machine: it idles until its placement game bit is set, falls
 * and bounces to a resting height, bobs on a sine wave while drifting, then
 * homes on the player and, on contact, restores health and is collected.
 *
 * mode: 0 idle (wait for game bit) -> 2 bobbing; 1 falling/bounce;
 *       2 bobbing+seek player; 3 chasing/intercept; 4 collected; 5 reset.
 *
 * The standard object hooks (init/update/render/getExtraSize/...) are wired
 * through the DLL's ObjectDescriptor elsewhere; rendering uses a shared glow
 * draw helper (objRenderModelAndHitVolumes) and particle bursts come from
 * gPartfxInterface / objfx_spawnFlaggedTrailBurst.
 */
#include "main/dll/drakorenergystate_struct.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0241_drakorenergy.h"

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* DrakorEnergyState.mode values (see file header comment) */
#define DRAKORENERGY_PARTFX         0x357
#define DRAKORENERGY_MODE_IDLE      0 /* wait for the placement game bit */
#define DRAKORENERGY_MODE_FALLING   1 /* fall + bounce to a resting height */
#define DRAKORENERGY_MODE_BOBBING   2 /* sine bob + seek the player */
#define DRAKORENERGY_MODE_CHASING   3 /* intercept/chase, heal on contact */
#define DRAKORENERGY_MODE_COLLECTED 4 /* collected (hidden, no update) */
#define DRAKORENERGY_MODE_RESET     5 /* one-frame reset back to IDLE */

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;
extern f32 lbl_803E6278;
extern f32 gDrakorEnergyBounceRestitution;
extern f32 lbl_803E6284;
extern f32 gDrakorEnergyGravity;
extern f32 gDrakorEnergyPi;
extern f32 gDrakorEnergyPhaseDivisor;
extern f32 lbl_803E6294;
extern f32 gDrakorEnergyBobAmplitude;
extern f32 gDrakorEnergySeekRange;
extern f32 lbl_803DC168;
extern f32 gDrakorEnergyChaseSpeed;
extern int gDrakorEnergyHealAmount;
extern f32 lbl_803DC174;
extern s16 lbl_803DC178;

extern void objRenderModelAndHitVolumes(int obj, int p1, int p2, int p3, int p4, f32 scale);
extern int Obj_GetPlayerObject(void);
extern void objMove(int, f32, f32, f32);
extern f32 Vec_xzDistance(int, int);
extern void playerAddHealth(int obj, int amount);

extern int Obj_PredictInterceptPoint(GameObject*, f32, f32*, f32*);
extern void PSVECSubtract(f32*, f32*, f32*);
extern void PSVECNormalize(f32*, f32*);
extern void PSVECScale(f32*, f32*, f32);
extern void objfx_spawnFlaggedTrailBurst(int, f32, int, int, int, int);

void DrakorEnergy_func0B_nop(void)
{
}

int drakorenergy_setScale(int* obj)
{
    return ((DrakorEnergyState*)(int*)((GameObject*)obj)->extra)->mode == DRAKORENERGY_MODE_IDLE;
}

int drakorenergy_getExtraSize(void)
{
    return sizeof(DrakorEnergyState);
}
int drakorenergy_getObjectTypeId(void)
{
    return 0x0;
}

void drakorenergy_free(void)
{
}

void drakorenergy_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    DrakorEnergyState* state = (obj)->extra;
    u32 mode = state->mode;
    if (mode != DRAKORENERGY_MODE_IDLE && mode != DRAKORENERGY_MODE_COLLECTED)
    {
        objRenderModelAndHitVolumes((int)obj, p1, p2, p3, p4, lbl_803E6278);
    }
}

void drakorenergy_hitDetect(void)
{
}

void drakorenergy_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int placement;
    int player;
    f32 zeroF;
    f32 dist;
    f32 spd;
    f32 interceptPt[3];
    f32 seekDir[3];
    s16 colorRGB[12];

    player = Obj_GetPlayerObject();
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (((DrakorEnergyState*)state)->mode)
    {
    case DRAKORENERGY_MODE_IDLE:
        if (mainGetBit(((DrakorenergyPlacement*)placement)->gameBitId) == 1)
        {
            ((DrakorEnergyState*)state)->mode = DRAKORENERGY_MODE_BOBBING;
        }
        break;
    case DRAKORENERGY_MODE_FALLING:
        if (((DrakorEnergyState*)state)->startY - ((GameObject*)obj)->anim.localPosY > (zeroF = lbl_803E627C))
        {
            ((GameObject*)obj)->anim.velocityY = gDrakorEnergyBounceRestitution * -((GameObject*)obj)->anim.velocityY;
            dist = (((GameObject*)obj)->anim.velocityY >= zeroF) ? ((GameObject*)obj)->anim.velocityY
                                                                 : -((GameObject*)obj)->anim.velocityY;
            if (dist < lbl_803E6284)
            {
                ((DrakorEnergyState*)state)->mode = DRAKORENERGY_MODE_BOBBING;
                zeroF = lbl_803E627C;
                ((GameObject*)obj)->anim.velocityX = zeroF;
                ((GameObject*)obj)->anim.velocityZ = zeroF;
                break;
            }
        }
        ((GameObject*)obj)->anim.velocityY += gDrakorEnergyGravity;
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        colorRGB[2] = 0xff;
        colorRGB[1] = 0xff - ((DrakorEnergyState*)state)->phase % 0x500;
        colorRGB[0] = 0xff;
        (*gPartfxInterface)->spawnObject((void*)obj, DRAKORENERGY_PARTFX, colorRGB, 0, -1, NULL);
        break;
    case DRAKORENERGY_MODE_BOBBING:
        ((GameObject*)obj)->anim.velocityY =
            gDrakorEnergyBobAmplitude *
            mathSinf(gDrakorEnergyPi * (f32)((DrakorEnergyState*)state)->phase / gDrakorEnergyPhaseDivisor);
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            gDrakorEnergySeekRange)
        {
            ((DrakorEnergyState*)state)->mode = DRAKORENERGY_MODE_CHASING;
        }
        objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        break;
    case DRAKORENERGY_MODE_CHASING:
        dist = Vec_xzDistance(obj + 0x18, player + 0x18);
        if (dist < lbl_803DC168)
        {
            playerAddHealth(player, gDrakorEnergyHealAmount);
            Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
            ((DrakorEnergyState*)state)->mode = DRAKORENERGY_MODE_COLLECTED;
        }
        else
        {
            spd = gDrakorEnergyChaseSpeed;
            Obj_PredictInterceptPoint((GameObject*)(player), spd / lbl_803E6294, (f32*)(obj + 0xc), interceptPt);
            PSVECSubtract(interceptPt, (f32*)(obj + 0xc), seekDir);
            PSVECNormalize(seekDir, seekDir);
            if (dist < spd)
            {
                spd = dist;
            }
            PSVECScale(seekDir, (f32*)(obj + 0x24), spd);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            colorRGB[2] = 0xff;
            colorRGB[1] = 0;
            colorRGB[0] = 0xff;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        }
        break;
    case DRAKORENERGY_MODE_RESET:
        ((DrakorEnergyState*)state)->mode = DRAKORENERGY_MODE_IDLE;
        break;
    }
    *(s16*)obj += lbl_803DC178;
    ((DrakorEnergyState*)state)->phase += framesThisStep * 0x500;
}

void drakorenergy_init(int* obj, u8* init)
{
    DrakorEnergyState* state;
    DrakorenergyPlacement* placement = (DrakorenergyPlacement*)init;
    f32 fz;
    state = ((GameObject*)obj)->extra;
    state->mode = DRAKORENERGY_MODE_RESET;
    ((GameObject*)obj)->anim.localPosX = placement->posX;
    ((GameObject*)obj)->anim.localPosY = placement->posY;
    ((GameObject*)obj)->anim.localPosZ = placement->posZ;
    fz = lbl_803E627C;
    ((GameObject*)obj)->anim.velocityZ = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = lbl_803E62A0;
    state->phase = randomGetRange(0, 0xffff);
    if (mainGetBit(placement->gameBitId) != 0)
    {
        state->mode = DRAKORENERGY_MODE_COLLECTED;
    }
}

void drakorenergy_release(void)
{
}

void drakorenergy_initialise(void)
{
}
