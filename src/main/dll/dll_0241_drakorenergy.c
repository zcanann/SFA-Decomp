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
 * draw helper (objRenderFn_8003b8f4) and particle bursts come from
 * gPartfxInterface / objfx_spawnFlaggedTrailBurst.
 */
#include "main/dll/drakorenergystate_struct.h"

#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"

extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(int obj, int p1, int p2, int p3, int p4, f32 scale);
extern u32 randomGetRange(int min, int max);
extern int Obj_GetPlayerObject(void);
extern void objMove(int, f32, f32, f32);
extern f32 Vec_distance(int, int);
extern f32 Vec_xzDistance(int, int);
extern void playerAddHealth(int, int);
extern void Sfx_PlayFromObject(int, int);
extern f32 mathSinf(f32);
extern void Obj_PredictInterceptPoint(int, int, f32*, f32);
extern void PSVECSubtract(f32*, f32*, f32*);
extern void PSVECNormalize(f32*, f32*);
extern void PSVECScale(f32*, f32*, f32);
extern void objfx_spawnFlaggedTrailBurst(int, f32, int, int, int, int);
extern f32 timeDelta;
extern u8 framesThisStep;

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

typedef struct DrakorenergyPlacement
{
    u8 pad_0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad_18[0x19 - 0x18];
    u8 unk19;
    u8 pad_1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad_1F[0x20 - 0x1F];
    s16 gameBitId;
    u8 pad_22[0x24 - 0x22];
    s16 unk24;
    u8 pad_26[0x2B - 0x26];
    u8 unk2B;
    u8 pad_2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad_2F[0x30 - 0x2F];
} DrakorenergyPlacement;

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;
extern f32 lbl_803E6278;
extern f32 lbl_803E6280;
extern f32 lbl_803E6284;
extern f32 lbl_803E6288;
extern f32 lbl_803E628C;
extern f32 lbl_803E6290;
extern f32 lbl_803E6294;
extern f32 lbl_803DC160;
extern f32 lbl_803DC164;
extern f32 lbl_803DC168;
extern f32 lbl_803DC16C;
extern int lbl_803DC170;
extern f32 lbl_803DC174;
extern s16 lbl_803DC178;

void DrakorEnergy_func0B_nop(void)
{
}

void drakorenergy_free(void)
{
}

void drakorenergy_hitDetect(void)
{
}

void drakorenergy_release(void)
{
}

void drakorenergy_initialise(void)
{
}

void drakorenergy_init(int* obj, u8* init)
{
    DrakorEnergyState* sub;
    DrakorenergyPlacement* placement = (DrakorenergyPlacement*)init;
    f32 fz;
    sub = ((GameObject*)obj)->extra;
    sub->mode = 5;
    ((GameObject*)obj)->anim.localPosX = placement->unk8;
    ((GameObject*)obj)->anim.localPosY = placement->unkC;
    ((GameObject*)obj)->anim.localPosZ = placement->unk10;
    fz = lbl_803E627C;
    ((GameObject*)obj)->anim.velocityZ = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = lbl_803E62A0;
    sub->phase = randomGetRange(0, 0xffff);
    if (GameBit_Get(placement->gameBitId) != 0)
    {
        sub->mode = 4;
    }
}

int drakorenergy_getExtraSize(void) { return sizeof(DrakorEnergyState); }
int drakorenergy_getObjectTypeId(void) { return 0x0; }

void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    DrakorEnergyState* inner = ((GameObject*)obj)->extra;
    u32 t = inner->mode;
    if (t != 0 && t != 4)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E6278);
    }
}

int DrakorEnergy_setScale(int* obj) { return ((DrakorEnergyState*)(int*)((GameObject*)obj)->extra)->mode == 0; }

void drakorenergy_update(int obj)
{
    int blob = *(int*)&((GameObject*)obj)->extra;
    int data;
    int player;
    f32 v;
    f32 dist;
    f32 spd;
    f32 v1[3];
    f32 v2[3];
    s16 trio[12];

    player = Obj_GetPlayerObject();
    data = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (((DrakorEnergyState*)blob)->mode)
    {
    case 0:
        if (GameBit_Get(((DrakorenergyPlacement*)data)->gameBitId) == 1)
        {
            ((DrakorEnergyState*)blob)->mode = 2;
        }
        break;
    case 1:
        if (((DrakorEnergyState*)blob)->startY - ((GameObject*)obj)->anim.localPosY > (v = lbl_803E627C))
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E6280 * -((GameObject*)obj)->anim.velocityY;
            dist = (((GameObject*)obj)->anim.velocityY >= v) ? ((GameObject*)obj)->anim.velocityY : -((GameObject*)obj)->anim.velocityY;
            if (dist < lbl_803E6284)
            {
                ((DrakorEnergyState*)blob)->mode = 2;
                v = lbl_803E627C;
                ((GameObject*)obj)->anim.velocityX = v;
                ((GameObject*)obj)->anim.velocityZ = v;
                break;
            }
        }
        ((GameObject*)obj)->anim.velocityY += lbl_803E6288;
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        trio[2] = 0xff;
        trio[1] = 0xff - ((DrakorEnergyState*)blob)->phase % 0x500;
        trio[0] = 0xff;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x357, trio, 0, -1, NULL);
        break;
    case 2:
        ((GameObject*)obj)->anim.velocityY = lbl_803DC160 * mathSinf(
            lbl_803E628C * (f32)((DrakorEnergyState*)blob)->phase / lbl_803E6290);
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        if (Vec_distance(obj + 0x18, player + 0x18) < lbl_803DC164)
        {
            ((DrakorEnergyState*)blob)->mode = 3;
        }
        objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        break;
    case 3:
        dist = Vec_xzDistance(obj + 0x18, player + 0x18);
        if (dist < lbl_803DC168)
        {
            playerAddHealth(player, lbl_803DC170);
            Sfx_PlayFromObject(obj, 0x49);
            ((DrakorEnergyState*)blob)->mode = 4;
        }
        else
        {
            spd = lbl_803DC16C;
            Obj_PredictInterceptPoint(player, obj + 0xc, v1, spd / lbl_803E6294);
            PSVECSubtract(v1, (f32*)(obj + 0xc), v2);
            PSVECNormalize(v2, v2);
            if (dist < spd)
            {
                spd = dist;
            }
            PSVECScale(v2, (f32*)(obj + 0x24), spd);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            trio[2] = 0xff;
            trio[1] = 0;
            trio[0] = 0xff;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        }
        break;
    case 5:
        ((DrakorEnergyState*)blob)->mode = 0;
        break;
    }
    *(s16*)obj += lbl_803DC178;
    ((DrakorEnergyState*)blob)->phase += framesThisStep * 0x500;
}
