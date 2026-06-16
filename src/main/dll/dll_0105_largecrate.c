#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/explodable_state.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/audio/sfx_ids.h"

#define SMALLBASKET_LINKED_ID_BASE 0x40000
#define SMALLBASKET_ROB_WAVE_DIRECT_ID 0x66
#define SMALLBASKET_ROB_WAVE_ID_65D0 0x65d0
#define SMALLBASKET_ROB_WAVE_ID_65D2 0x65d2
#define SMALLBASKET_ROB_WAVE_ID_65D5 0x65d5
#define SMALLBASKET_ROB_WAVE_ID_65D6 0x65d6
#define SMALLBASKET_ROB_WAVE_ID_65D7 0x65d7
#define GAMEBIT_SFX_MUTE 0xa71

extern u8 Obj_IsLoadingLocked(void);
extern int GameBit_Set(int bit, int value);
extern char* Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern u32 randomGetRange(int min, int max);
extern f32 sqrtf(f32 x);
extern void vecRotateZXY(void* p, f32* v);
extern int getAngle(f32 a, f32 b);
extern int Obj_GetPlayerObject(void);
extern void ObjHits_EnableObject(int obj);
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern int ObjHits_GetPriorityHitWithPosition(int obj, void* info, int* a, int* b, f32* x, f32* y, f32* z);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern int Sfx_IsPlayingFromObject(int obj, u32 sfxId);
extern void Sfx_PlayFromObject(int obj, u32 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern f32 lbl_803E39A8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f32 lbl_803E39D0;
extern f32 lbl_803E39D4;
extern f32 lbl_803E39D8;
extern f32 lbl_803E39DC;
extern f32 lbl_803E39E0;
extern f32 lbl_803E39E4;

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} Vec3L;

typedef struct
{
    s16 h0;
    s16 h1;
    s16 h2;
    f32 fx;
    f32 fy;
    f32 fz;
    f32 fw;
} ExplodeArgs;

f32 fn_80183204(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    return lbl_803E39AC - (f32)(u32)
    state[0x13] / (f32)(u32)
    state[0x28];
}

void fn_80183250(int obj, int def)
{
    extern int GameBit_Get(int id);
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int*)&((GameObject*)obj)->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    if ((*(u16*)(*(int*)&((GameObject*)obj)->anim.parent + 0xb0) & 0x1000) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)(def + 0x24);
        ((GameObject*)obj)->anim.velocityX = 0.0f;
    }
    else
    {
        oldVel = ((GameObject*)obj)->anim.velocityX;
        sum = *(s16*)(*(int*)&((GameObject*)obj)->anim.parent + 0x4) + *(u16*)(def + 0x20);
        ((GameObject*)obj)->anim.velocityX = -(f32)sum / *(f32*)(def + 0x1c);
        if ((oldVel <= 0.0f && ((GameObject*)obj)->anim.velocityX >= 0.0f) ||
            (oldVel >= 0.0f && ((GameObject*)obj)->anim.velocityX <= 0.0f))
        {
            v = *(u32*)(state31 + 0x14);
            adj = v - SMALLBASKET_LINKED_ID_BASE;
            if ((adj == SMALLBASKET_ROB_WAVE_ID_65D7) ||
                ((adj - SMALLBASKET_ROB_WAVE_ID_65D5) <=
                    (SMALLBASKET_ROB_WAVE_ID_65D6 - SMALLBASKET_ROB_WAVE_ID_65D5)) ||
                (v == SMALLBASKET_ROB_WAVE_DIRECT_ID) || (adj == SMALLBASKET_ROB_WAVE_ID_65D0) ||
                (adj == SMALLBASKET_ROB_WAVE_ID_65D2))
            {
                if (Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <
                    lbl_803E39BC)
                {
                    if ((u32)GameBit_Get(GAMEBIT_SFX_MUTE) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXfend_rob_wave);
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + ((GameObject*)obj)->anim.velocityX;
        if (((GameObject*)obj)->anim.localPosX > (limit = lbl_803E39C0 + *(f32*)(def + 0x24)))
        {
            ((GameObject*)obj)->anim.localPosX = limit;
        }
        else
        {
            limit = *(f32*)(def + 0x24) - lbl_803E39C4;
            if (((GameObject*)obj)->anim.localPosX < limit)
            {
                ((GameObject*)obj)->anim.localPosX = limit;
            }
        }
    }
}

int fn_801833E4(int obj, int player, int state)
{
    GameObject* playerObj;
    ExplodeArgs blk;
    char* setup;
    char* newObj;
    f32 len;
    int angle;

    playerObj = (GameObject*)player;
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    GameBit_Set(*(s16*)(state + 0xe), 1);
    switch (*(u8*)(state + 0x11))
    {
    case 1:
        setup = Obj_AllocObjectSetup(0x24, 0x3d3);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 400;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                 *(int*)&((GameObject*)obj)->anim.parent);
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        len = ((GameObject*)newObj)->anim.velocityX * ((GameObject*)newObj)->anim.velocityX +
            ((GameObject*)newObj)->anim.velocityZ * ((GameObject*)newObj)->anim.velocityZ;
        if (len != lbl_803E39B8)
        {
            len = sqrtf(len);
            ((GameObject*)newObj)->anim.velocityX = ((GameObject*)newObj)->anim.velocityX / len;
            ((GameObject*)newObj)->anim.velocityZ = ((GameObject*)newObj)->anim.velocityZ / len;
        }
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)newObj)->anim.velocityX *
            -(lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E39AC
        )
        ;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19)
        )
        ;
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.fy = lbl_803E39B8;
        blk.fz = lbl_803E39B8;
        blk.fw = lbl_803E39B8;
        blk.fx = lbl_803E39AC;
        blk.h2 = 0;
        blk.h1 = 0;
        blk.h0 = (s16)randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
        ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) &
            0xffff);
        if (angle > 0x8000)
        {
            angle = angle - 0xffff;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xffff;
        }
        *(s16*)newObj = angle;
        break;
    case 2:
        setup = Obj_AllocObjectSetup(0x24, 0x3d4);
        *(s8*)(setup + 0x18) = (s8)randomGetRange(-0x7f, 0x7e);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 400;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                 *(int*)&((GameObject*)obj)->anim.parent);
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        len = ((GameObject*)newObj)->anim.velocityX * ((GameObject*)newObj)->anim.velocityX +
            ((GameObject*)newObj)->anim.velocityZ * ((GameObject*)newObj)->anim.velocityZ;
        if (len != lbl_803E39B8)
        {
            len = sqrtf(len);
            ((GameObject*)newObj)->anim.velocityX = ((GameObject*)newObj)->anim.velocityX / len;
            ((GameObject*)newObj)->anim.velocityZ = ((GameObject*)newObj)->anim.velocityZ / len;
        }
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)newObj)->anim.velocityX *
            -(lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E39AC
        )
        ;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19)
        )
        ;
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.fy = lbl_803E39B8;
        blk.fz = lbl_803E39B8;
        blk.fw = lbl_803E39B8;
        blk.fx = lbl_803E39AC;
        blk.h2 = 0;
        blk.h1 = 0;
        blk.h0 = (s16)randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
        ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) &
            0xffff);
        if (angle > 0x8000)
        {
            angle = angle - 0xffff;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xffff;
        }
        *(s16*)newObj = angle;
        break;
    case 3:
        setup = Obj_AllocObjectSetup(0x24, 0x3d5);
        *(s8*)(setup + 0x18) = (s8)randomGetRange(-0x7f, 0x7e);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x1a) = 2000;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                 *(int*)&((GameObject*)obj)->anim.parent);
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)obj)->anim.localPosX - playerObj->anim.localPosX;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)obj)->anim.localPosZ - playerObj->anim.localPosZ;
        len = ((GameObject*)newObj)->anim.velocityX * ((GameObject*)newObj)->anim.velocityX +
            ((GameObject*)newObj)->anim.velocityZ * ((GameObject*)newObj)->anim.velocityZ;
        if (len != lbl_803E39B8)
        {
            len = sqrtf(len);
            ((GameObject*)newObj)->anim.velocityX = ((GameObject*)newObj)->anim.velocityX / len;
            ((GameObject*)newObj)->anim.velocityZ = ((GameObject*)newObj)->anim.velocityZ / len;
        }
        ((GameObject*)newObj)->anim.velocityX =
            ((GameObject*)newObj)->anim.velocityX *
            -(lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19) - lbl_803E39AC
        )
        ;
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)
        randomGetRange(0, 0x19)
        )
        ;
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.fy = lbl_803E39B8;
        blk.fz = lbl_803E39B8;
        blk.fw = lbl_803E39B8;
        blk.fx = lbl_803E39AC;
        blk.h2 = 0;
        blk.h1 = 0;
        blk.h0 = (s16)randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
        ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) &
            0xffff);
        if (angle > 0x8000)
        {
            angle = angle - 0xffff;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xffff;
        }
        *(s16*)newObj = angle;
        break;
    case 5:
    case 6:
        if (*(u8*)(state + 0x11) == 5)
        {
            setup = Obj_AllocObjectSetup(0x30, 0xb);
        }
        else
        {
            setup = Obj_AllocObjectSetup(0x30, 0x3cd);
        }
        *(u8*)(setup + 0x1a) = 0x14;
        *(s16*)(setup + 0x2c) = -1;
        *(s16*)(setup + 0x1c) = -1;
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E39C0 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)(setup + 0x24) = -1;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                 *(int*)&((GameObject*)obj)->anim.parent);
        (**(void (**)(f32, f32, f32))(**(int**)&((GameObject*)newObj)->anim.dll + 0x2c))(
            lbl_803E39B8, lbl_803E39AC, lbl_803E39B8);
        break;
    case 7:
    case 8:
        GameBit_Set(*(s16*)(state + 0xe), 1);
        break;
    case 9:
        if (Obj_IsLoadingLocked() != 0)
        {
            setup = Obj_AllocObjectSetup(0x24, 0x259);
            ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
            ((ObjPlacement*)setup)->posY = lbl_803E39A8 + ((GameObject*)obj)->anim.localPosY;
            ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
            *(u8*)(setup + 0x4) = 4;
            *(u8*)(setup + 0x6) = 200;
            *(s16*)(setup + 0x20) = -1;
            *(s16*)(setup + 0x1a) = 0x7f;
            Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                            *(int*)&((GameObject*)obj)->anim.parent);
        }
        break;
    }
    return 0;
}

int largecrate_getExtraSize(void)
{
    return 0x2c;
}

int largecrate_getObjectTypeId(void)
{
    return 0;
}

void largecrate_render(int obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    int state;
    s16 timer;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((*gMapEventInterface)->shouldNotSaveTime(*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14)) == 0)
        ||
        (((timer = ((ExplodableState*)state)->explodeTimer) != 0) && (timer <= 0x32)) ||
        (((ExplodableState*)state)->animTimer > lbl_803E39B8))
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        if (((GameObject*)obj)->unkF8 != 0)
        {
            if (renderState != -1)
            {
                ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
                return;
            }
        }
        else if (renderState == 0)
        {
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
            return;
        }
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E39AC);
    }
}

void largecrate_hitDetect(void)
{
}

void largecrate_update(int obj)
{
    extern int* lbl_803DDAC8;
    extern void ObjHits_DisableObject(int obj);
    int player;
    int def;
    int state;
    Vec3L pos;
    Vec3L lightPos;
    u8 hitInfo[4];
    int local40;
    int hitDamage;
    f32 animSpeed;
    int hit;
    int level;
    f32 thresh;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    local40 = -1;
    animSpeed = lbl_803E39AC;
    (*gSkyInterface)->getClockTime(&animSpeed);
    state = *(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)def)->mapId) == 0)
    {
        ObjHits_DisableObject(obj);
    }
    else
    {
        if (((ExplodableState*)state)->animTimer > (thresh = lbl_803E39B8))
        {
            ((GameObject*)obj)->anim.alpha = 0;
            if (*(int*)state != -1)
            {
                ((ExplodableState*)state)->animTimer = -(timeDelta * animSpeed - ((ExplodableState*)state)->animTimer);
                if (((ExplodableState*)state)->animTimer <= thresh)
                {
                    if (!(Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) >
                        lbl_803E39D0))
                    {
                        ((ExplodableState*)state)->animTimer = lbl_803E39AC;
                    }
                    else
                    {
                        ((ExplodableState*)state)->animTimer = lbl_803E39B8;
                        ((ExplodableState*)state)->explodeTimer = 0;
                        ObjHits_EnableObject(obj);
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
                        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                    }
                }
            }
        }
        else
        {
            level = (int)(lbl_803E39DC * timeDelta + (f32)(u32)((GameObject*)obj)->anim.alpha);
            if (level > 0xff)
            {
                level = 0xff;
            }
            ((GameObject*)obj)->anim.alpha = level;
            if (((ExplodableState*)state)->explodeTimer != 0)
            {
                ObjHits_DisableObject(obj);
                if ((((ExplodableState*)state)->explodeTimer -= framesThisStep) <= 0)
                {
                    if (*(int*)state > 0)
                    {
                        ((ExplodableState*)state)->animTimer = lbl_803E39AC;
                        (*gMapEventInterface)->addTime(((ObjPlacement*)def)->mapId, (f32) * (int*)state);
                    }
                    else
                    {
                        ((ExplodableState*)state)->animTimer = lbl_803E39AC;
                    }
                    ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)def)->posX;
                    ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
                    ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)def)->posZ;
                    ((GameObject*)obj)->anim.previousLocalPosX = ((ObjPlacement*)def)->posX;
                    ((GameObject*)obj)->anim.previousLocalPosY = ((ObjPlacement*)def)->posY;
                    ((GameObject*)obj)->anim.previousLocalPosZ = ((ObjPlacement*)def)->posZ;
                    thresh = lbl_803E39B8;
                    ((GameObject*)obj)->anim.velocityX = thresh;
                    ((GameObject*)obj)->anim.velocityY = thresh;
                    ((GameObject*)obj)->anim.velocityZ = thresh;
                }
                if (((ExplodableState*)state)->explodeTimer <= 0x32)
                {
                    return;
                }
            }
            ((GameObject*)obj)->anim.rotY = ((ExplodableState*)state)->spinSpeed;
            ((ExplodableState*)state)->spinSpeed = (f32)((ExplodableState*)state)->spinSpeed * lbl_803E39E0;
            if ((((GameObject*)obj)->anim.rotY < 10) && (-10 < ((GameObject*)obj)->anim.rotY))
            {
                ((GameObject*)obj)->anim.rotY = 0;
            }
            hit = ObjHits_GetPriorityHitWithPosition(obj, hitInfo, &local40, &hitDamage, &pos.x, &pos.y, &pos.z);
            if (hit == 0x10)
            {
                Obj_StartModelFadeIn(obj, 300);
                hit = 0;
            }
            if ((hit != 0) && (((GameObject*)obj)->anim.parent == NULL))
            {
                ((ExplodableState*)state)->damageTaken = ((ExplodableState*)state)->damageTaken + hitDamage;
                Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
                pos.x = pos.x + playerMapOffsetX;
                pos.z = pos.z + playerMapOffsetZ;
                objLightFn_8009a1dc((void*)obj, lbl_803E39E4, &lightPos, 1, 0);
                if (((ExplodableState*)state)->damageTaken < ((ExplodableState*)state)->damageThreshold)
                {
                    if (Sfx_IsPlayingFromObject(0, (u16)((ExplodableState*)state)->hitSfxId) == 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((ExplodableState*)state)->hitSfxId);
                    }
                    if (((GameObject*)obj)->anim.seqId == 0x3de)
                    {
                        ((ExplodableState*)state)->spinSpeed = (s16)randomGetRange(600, 800);
                    }
                }
                else
                {
                    Sfx_StopObjectChannel(obj, 0x7f);
                    (**(void (**)(int, int, int, int, int, int))(*lbl_803DDAC8 + 0x4))(
                        obj, 1, 0, 2, -1, 0);
                    if (Sfx_IsPlayingFromObject(0, (u16)((ExplodableState*)state)->explodeSfxId) == 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((ExplodableState*)state)->explodeSfxId);
                    }
                    ((ExplodableState*)state)->explodeTimer = 0x32;
                    ((ExplodableState*)state)->damageTaken = 0;
                    fn_801833E4(obj, player, state);
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                }
            }
            vec3f_distanceSquared(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
            if ((((ExplodableState*)state)->randomTimer -= framesThisStep) <= 0)
            {
                ((ExplodableState*)state)->randomTimer = (s16)(randomGetRange(0, 100) + 0x12c);
            }
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                fn_80183250(obj, state);
            }
        }
    }
}

extern ModgfxInterface** gModgfxInterface;

void largecrate_free(int obj)
{
    extern int* lbl_803DDAC8;
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(lbl_803DDAC8);
}

int LargeCrate_SeqFn(int* obj)
{
    if (((GameObject*)obj)->seqIndex != -1)
    {
        (*gCameraInterface)->setTargetReticleOverride((int)obj);
    }
    return 0;
}

#include "main/dll/cfforcefield.h"
#include "main/game_object.h"
#include "main/dll/cfforcefield_state.h"
#include "main/resource.h"

extern uint GameBit_Get(int eventId);

extern f32 lbl_803E39E8;

typedef union LargeCrateVariantRemap
{
    s16 entries[6];
    int words[3];
} LargeCrateVariantRemap;

extern LargeCrateVariantRemap lbl_802C2280;
extern LargeCrateVariantRemap lbl_802C228C;

void largecrate_init(int obj, u8* initData)
{
    extern void* lbl_803DDAC8;
    extern void ObjHits_DisableObject(u32 obj);
    int state;
    u32 r3rand;
    f32 fr;
    LargeCrateVariantRemap constArrA;
    LargeCrateVariantRemap constArrB;
    short id;

    constArrA = lbl_802C2280;
    constArrB = lbl_802C228C;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)LargeCrate_SeqFn;
    *(short*)obj = (short)((int)(signed char)initData[0x18] << 8);
    ((CfForcefieldState*)state)->enableGameBit = *(short*)(initData + 0x1e);

    id = *(short*)(initData + 0x1c);
    if (id == LARGECRATE_TIMER_SENTINEL_DISABLED)
    {
        *(int*)state = LARGECRATE_TIMER_SENTINEL_DISABLED;
    }
    else if (id == LARGECRATE_TIMER_SENTINEL_FOREVER)
    {
        *(int*)state = -1;
    }
    else
    {
        *(int*)state = (int)id * LARGECRATE_TIMER_SCALE_FRAMES;
    }

    if (GameBit_Get((int)((CfForcefieldState*)state)->enableGameBit) != 0)
    {
        *(float*)(state + 4) = lbl_803E39AC;
        ObjHits_DisableObject((u32)obj);
    }

    ((CfForcefieldState*)state)->unk11 = initData[0x19];
    lbl_803DDAC8 = Resource_Acquire(LARGECRATE_RESOURCE_ID, LARGECRATE_RESOURCE_MODE);
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX);
    ((CfForcefieldState*)state)->randomTimer = (short)(r3rand + LARGECRATE_RANDOM_DELAY_BASE);
    ((CfForcefieldState*)state)->countdown = LARGECRATE_DEFAULT_COUNTDOWN;
    ((CfForcefieldState*)state)->unk12 = (u8) * (short*)(initData + 0x1a);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | LARGECRATE_OBJECT_FLAGS);
    *(short*)obj = (short)((int)(signed char)initData[0x18] << 8);

    id = ((GameObject*)obj)->anim.seqId;
    if (id == LARGECRATE_VARIANT_A)
    {
        ((CfForcefieldState*)state)->unk11 = (u8)constArrA.entries[((CfForcefieldState*)state)->unk11];
        ((CfForcefieldState*)state)->sfxIdA = LARGECRATE_VARIANT_A_SFX_A;
        ((CfForcefieldState*)state)->sfxIdB = LARGECRATE_VARIANT_A_SFX_B;
    }
    else if (id == LARGECRATE_VARIANT_B || id == LARGECRATE_VARIANT_C)
    {
        ((CfForcefieldState*)state)->unk11 = (u8)constArrB.entries[((CfForcefieldState*)state)->unk11];
        ((CfForcefieldState*)state)->sfxIdA = LARGECRATE_VARIANT_B_SFX_A;
        ((CfForcefieldState*)state)->sfxIdB = LARGECRATE_VARIANT_B_SFX_B;
    }

    ((CfForcefieldState*)state)->unk20 = 0;
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_BOB_MAX);
    fr = (float)(int)r3rand;
    fr = lbl_803E39E8 + fr;
    *(float*)(state + 0x1c) = fr;
    *(float*)(state + 0x24) = ((GameObject*)obj)->anim.localPosX;

    if (((GameObject*)obj)->anim.seqId == LARGECRATE_VARIANT_C)
    {
        ((CfForcefieldState*)state)->unk28 = 0;
    }
    else
    {
        ((CfForcefieldState*)state)->unk28 = 2;
    }
}

void largecrate_release(void)
{
}

void largecrate_initialise(void)
{
}
