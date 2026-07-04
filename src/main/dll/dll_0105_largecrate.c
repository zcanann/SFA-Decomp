/*
 * largecrate (DLL 0x105) - destructible crates that drop a pickup when broken.
 *
 * The obj+0xB8 extra record is LargeCrateState (live-verified by reading a
 * crate's struct in Dolphin and breaking it to trace the drop). The crate
 * takes hits (damageTaken) until damageThreshold, then plays explodeSfxId,
 * hides for breakTimer frames, and spawns its drop contents via
 * largecrate_spawnDropContents (dispatch on dropType): fruit (0x3D3/0x3D4/
 * 0x3D5) or a collectible object (type 0xB, DLL 0x00ED) such as a +health
 * food item, launched outward. breakTimeBonus is fed to mapEvent addTime()
 * on break; brokenGameBit persists the broken state across loads. seqId
 * selects the crate variant (A=0x3DE, B=0x49F, C=0x7BE), each with its own
 * hit/explode sfx pair. largecrate_getReticleDistance returns crate integrity
 * (1.0 - damageTaken/damageThreshold) for the camera reticle, read cross-DLL
 * by camcontrol; largecrate_updateConveyorSlide drives the conveyor-belt
 * slide for parented crates.
 *
 * GAMEBIT_SFX_MUTE (0xa71) gates the rob-wave warning sfx.
 */
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/dll_0105_largecrate.h"
#include "main/dll/largecrate_state.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

#define LARGECRATE_OBJFLAG_PARENT_SLACK 0x1000
#define LARGECRATE_LINKED_ID_BASE 0x40000
#define LARGECRATE_ROB_WAVE_DIRECT_ID 0x66
#define LARGECRATE_ROB_WAVE_ID_65D0 0x65d0
#define LARGECRATE_ROB_WAVE_ID_65D2 0x65d2
#define LARGECRATE_ROB_WAVE_ID_65D5 0x65d5
#define LARGECRATE_ROB_WAVE_ID_65D6 0x65d6
#define LARGECRATE_ROB_WAVE_ID_65D7 0x65d7
#define GAMEBIT_SFX_MUTE 0xa71

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern int randomGetRange(int lo, int hi);
extern f32 sqrtf(f32 x);
extern void vecRotateZXY(void* p, f32* v);
extern int getAngle(float y, float x);
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);



extern ModgfxInterface** gModgfxInterface;
extern int* lbl_803DDAC8;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E39A8;
extern const f32 lbl_803E39AC;
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
extern f32 lbl_803E39E8;

typedef union LargeCrateVariantRemap
{
    s16 entries[6];
    int words[3];
} LargeCrateVariantRemap;

extern LargeCrateVariantRemap gLargeCrateVariantARemap;
extern LargeCrateVariantRemap gLargeCrateVariantBRemap;

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} Vec3f;

typedef struct
{
    s16 rotZ;
    s16 rotX;
    s16 rotY;
    f32 scaleX;
    f32 scaleY;
    f32 scaleZ;
    f32 scaleW;
} ExplodeArgs;

/* Spawn-setup buffers seeded by largecrate_spawnDropContents. Each child class
 * (dropType) reuses ObjPlacement's pos/color head and adds its own fields; the
 * store width at each offset is class-specific (see the target stb/sth). */
typedef struct CrateFragmentSetup /* dropType 1/2/3 (0x3d3/0x3d4/0x3d5) */
{
    ObjPlacement head; /* 0x00 */
    s8 spinSeed;       /* 0x18 */
    u8 pad19;          /* 0x19 */
    s16 field1A;       /* 0x1a */
} CrateFragmentSetup;

typedef struct CrateGasSetup /* dropType 5/6 (0xb/0x3cd) */
{
    ObjPlacement head;        /* 0x00 */
    u8 pad18[0x1a - 0x18];
    u8 field1A;               /* 0x1a */
    u8 pad1B;                 /* 0x1b */
    s16 field1C;              /* 0x1c */
    u8 pad1E[0x24 - 0x1e];
    s16 field24;              /* 0x24 */
    u8 pad26[0x2c - 0x26];
    s16 field2C;              /* 0x2c */
} CrateGasSetup;

typedef struct CratePickupSetup /* dropType 9 (0x259) */
{
    ObjPlacement head;        /* 0x00 */
    u8 pad18[0x1a - 0x18];
    s16 field1A;              /* 0x1a */
    u8 pad1C[0x20 - 0x1c];
    s16 field20;              /* 0x20 */
} CratePickupSetup;

void largecrate_updateConveyorSlide(int obj, int def);
void largecrate_update(int obj);
void largecrate_free(int obj);

f32 largecrate_getReticleDistance(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    return lbl_803E39AC - (f32)(u32)((LargeCrateState*)state)->damageTaken / (f32)(u32)((LargeCrateState*)state)->damageThreshold;
}

void largecrate_updateConveyorSlide(int obj, int def)
{
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int*)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if ((*(u16*)(*(int*)&((GameObject*)obj)->anim.parent + 0xb0) & LARGECRATE_OBJFLAG_PARENT_SLACK) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((LargeCrateState*)def)->homeX;
        ((GameObject*)obj)->anim.velocityX = 0.0f;
    }
    else
    {
        oldVel = ((GameObject*)obj)->anim.velocityX;
        sum = ((GameObject*)((GameObject*)obj)->anim.parent)->anim.rotZ + ((LargeCrateState*)def)->slideOffset;
        ((GameObject*)obj)->anim.velocityX = -(f32)sum / ((LargeCrateState*)def)->slidePhase;
        if ((oldVel <= 0.0f && ((GameObject*)obj)->anim.velocityX >= 0.0f) ||
            (oldVel >= 0.0f && ((GameObject*)obj)->anim.velocityX <= 0.0f))
        {
            v = *(u32*)(state31 + 0x14);
            adj = v - LARGECRATE_LINKED_ID_BASE;
            if ((adj == LARGECRATE_ROB_WAVE_ID_65D7) ||
                ((adj - LARGECRATE_ROB_WAVE_ID_65D5) <=
                    (LARGECRATE_ROB_WAVE_ID_65D6 - LARGECRATE_ROB_WAVE_ID_65D5)) ||
                (v == LARGECRATE_ROB_WAVE_DIRECT_ID) || (adj == LARGECRATE_ROB_WAVE_ID_65D0) ||
                (adj == LARGECRATE_ROB_WAVE_ID_65D2))
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
        if (((GameObject*)obj)->anim.localPosX > (limit = lbl_803E39C0 + ((LargeCrateState*)def)->homeX))
        {
            ((GameObject*)obj)->anim.localPosX = limit;
        }
        else
        {
            limit = ((LargeCrateState*)def)->homeX - lbl_803E39C4;
            if (((GameObject*)obj)->anim.localPosX < limit)
            {
                ((GameObject*)obj)->anim.localPosX = limit;
            }
        }
    }
}

int largecrate_spawnDropContents(int obj, int player, int state)
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
    GameBit_Set(((LargeCrateState*)state)->brokenGameBit, 1);
    switch (((LargeCrateState*)state)->dropType)
    {
    case 1:
        setup = Obj_AllocObjectSetup(0x24, 0x3d3);
        ((CrateFragmentSetup*)setup)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((CrateFragmentSetup*)setup)->head.posY = ((GameObject*)obj)->anim.localPosY;
        ((CrateFragmentSetup*)setup)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((CrateFragmentSetup*)setup)->field1A = 400;
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
            -(lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E39AC);
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19));
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.scaleY = lbl_803E39B8;
        blk.scaleZ = lbl_803E39B8;
        blk.scaleW = lbl_803E39B8;
        blk.scaleX = lbl_803E39AC;
        blk.rotY = 0;
        blk.rotX = 0;
        blk.rotZ = randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
            ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) & 0xffff);
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
        ((CrateFragmentSetup*)setup)->spinSeed = randomGetRange(-0x7f, 0x7e);
        ((CrateFragmentSetup*)setup)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((CrateFragmentSetup*)setup)->head.posY = ((GameObject*)obj)->anim.localPosY;
        ((CrateFragmentSetup*)setup)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((CrateFragmentSetup*)setup)->field1A = 400;
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
            -(lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E39AC);
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19));
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.scaleY = lbl_803E39B8;
        blk.scaleZ = lbl_803E39B8;
        blk.scaleW = lbl_803E39B8;
        blk.scaleX = lbl_803E39AC;
        blk.rotY = 0;
        blk.rotX = 0;
        blk.rotZ = randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
            ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) & 0xffff);
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
        ((CrateFragmentSetup*)setup)->spinSeed = randomGetRange(-0x7f, 0x7e);
        ((CrateFragmentSetup*)setup)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((CrateFragmentSetup*)setup)->head.posY = ((GameObject*)obj)->anim.localPosY;
        ((CrateFragmentSetup*)setup)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((CrateFragmentSetup*)setup)->field1A = 2000;
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
            -(lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E39AC);
        ((GameObject*)newObj)->anim.velocityZ =
            ((GameObject*)newObj)->anim.velocityZ *
            (lbl_803E39AC - lbl_803E39D4 * (f32)(int)randomGetRange(0, 0x19));
        ((GameObject*)newObj)->anim.velocityY = lbl_803E39D8;
        blk.scaleY = lbl_803E39B8;
        blk.scaleZ = lbl_803E39B8;
        blk.scaleW = lbl_803E39B8;
        blk.scaleX = lbl_803E39AC;
        blk.rotY = 0;
        blk.rotX = 0;
        blk.rotZ = randomGetRange(-10000, 10000);
        vecRotateZXY(&blk, (f32*)(newObj + 0x24));
        angle = *(s16*)newObj -
            ((int)(s16)getAngle(((GameObject*)newObj)->anim.velocityX, -((GameObject*)newObj)->anim.velocityZ) & 0xffff);
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
        if (((LargeCrateState*)state)->dropType == 5)
        {
            setup = Obj_AllocObjectSetup(0x30, 0xb);
        }
        else
        {
            setup = Obj_AllocObjectSetup(0x30, 0x3cd);
        }
        ((CrateGasSetup*)setup)->field1A = 0x14;
        ((CrateGasSetup*)setup)->field2C = -1;
        ((CrateGasSetup*)setup)->field1C = -1;
        ((CrateGasSetup*)setup)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((CrateGasSetup*)setup)->head.posY = lbl_803E39C0 + ((GameObject*)obj)->anim.localPosY;
        ((CrateGasSetup*)setup)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((CrateGasSetup*)setup)->field24 = -1;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                 *(int*)&((GameObject*)obj)->anim.parent);
        (**(void (**)(int, f32, f32, f32))(**(int**)&((GameObject*)newObj)->anim.dll + 0x2c))(
            (int)newObj, lbl_803E39B8, lbl_803E39AC, lbl_803E39B8);
        break;
    case 7:
    case 8:
        GameBit_Set(((LargeCrateState*)state)->brokenGameBit, 1);
        break;
    case 9:
        if (Obj_IsLoadingLocked() != 0)
        {
            setup = Obj_AllocObjectSetup(0x24, 0x259);
            ((CratePickupSetup*)setup)->head.posX = ((GameObject*)obj)->anim.localPosX;
            ((CratePickupSetup*)setup)->head.posY = lbl_803E39A8 + ((GameObject*)obj)->anim.localPosY;
            ((CratePickupSetup*)setup)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
            ((CratePickupSetup*)setup)->head.color[0] = 4;
            ((CratePickupSetup*)setup)->head.color[2] = 200;
            ((CratePickupSetup*)setup)->field20 = -1;
            ((CratePickupSetup*)setup)->field1A = 0x7f;
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
        (((timer = ((LargeCrateState*)state)->breakTimer) != 0) && (timer <= 0x32)) ||
        (((LargeCrateState*)state)->animTimer > lbl_803E39B8))
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

void largecrate_hitDetect(int obj)
{
}

void largecrate_update(int obj)
{
    int player;
    int def;
    int state;
    Vec3f pos;
    Vec3f lightPos;
    u8 hitInfo[4];
    int hitType;
    int hitDamage;
    f32 animSpeed;
    int hit;
    int level;
    f32 thresh;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    hitType = -1;
    animSpeed = lbl_803E39AC;
    (*gSkyInterface)->getClockTime(&animSpeed);
    state = *(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)def)->mapId) == 0)
    {
        ObjHits_DisableObject(obj);
    }
    else
    {
        if (((LargeCrateState*)state)->animTimer > (thresh = lbl_803E39B8))
        {
            ((GameObject*)obj)->anim.alpha = 0;
            if (((LargeCrateState*)state)->breakTimeBonus != -1)
            {
                ((LargeCrateState*)state)->animTimer = -(timeDelta * animSpeed - ((LargeCrateState*)state)->animTimer);
                if (((LargeCrateState*)state)->animTimer <= thresh)
                {
                    if (!(Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) >
                        lbl_803E39D0))
                    {
                        ((LargeCrateState*)state)->animTimer = lbl_803E39AC;
                    }
                    else
                    {
                        ((LargeCrateState*)state)->animTimer = lbl_803E39B8;
                        ((LargeCrateState*)state)->breakTimer = 0;
                        ObjHits_EnableObject(obj);
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
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
            if (((LargeCrateState*)state)->breakTimer != 0)
            {
                ObjHits_DisableObject(obj);
                if ((((LargeCrateState*)state)->breakTimer -= framesThisStep) <= 0)
                {
                    if (((LargeCrateState*)state)->breakTimeBonus > 0)
                    {
                        ((LargeCrateState*)state)->animTimer = lbl_803E39AC;
                        (*gMapEventInterface)->addTime(((ObjPlacement*)def)->mapId, (f32) * (int*)state);
                    }
                    else
                    {
                        ((LargeCrateState*)state)->animTimer = lbl_803E39AC;
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
                if (((LargeCrateState*)state)->breakTimer <= 0x32)
                {
                    return;
                }
            }
            ((GameObject*)obj)->anim.rotY = ((LargeCrateState*)state)->spinSpeed;
            ((LargeCrateState*)state)->spinSpeed = (f32)((LargeCrateState*)state)->spinSpeed * lbl_803E39E0;
            if ((((GameObject*)obj)->anim.rotY < 10) && (-10 < ((GameObject*)obj)->anim.rotY))
            {
                ((GameObject*)obj)->anim.rotY = 0;
            }
            hit = ObjHits_GetPriorityHitWithPosition(obj, (int*)hitInfo, &hitType, (u32*)&hitDamage,
                                                     &pos.x, &pos.y, &pos.z);
            if (hit == 0x10)
            {
                Obj_StartModelFadeIn(obj, 300);
                hit = 0;
            }
            if ((hit != 0) && (((GameObject*)obj)->anim.parent == NULL))
            {
                ((LargeCrateState*)state)->damageTaken = ((LargeCrateState*)state)->damageTaken + hitDamage;
                Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
                pos.x = pos.x + playerMapOffsetX;
                pos.z = pos.z + playerMapOffsetZ;
                objLightFn_8009a1dc((void*)obj, lbl_803E39E4, &lightPos, 1, 0);
                if (((LargeCrateState*)state)->damageTaken < ((LargeCrateState*)state)->damageThreshold)
                {
                    if (Sfx_IsPlayingFromObject(0, (u16)((LargeCrateState*)state)->hitSfxId) == 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((LargeCrateState*)state)->hitSfxId);
                    }
                    if (((GameObject*)obj)->anim.seqId == LARGECRATE_VARIANT_A)
                    {
                        ((LargeCrateState*)state)->spinSpeed = randomGetRange(600, 800);
                    }
                }
                else
                {
                    Sfx_StopObjectChannel(obj, 0x7f);
                    (**(void (**)(int, int, int, int, int, int))(*lbl_803DDAC8 + 0x4))(
                        obj, 1, 0, 2, -1, 0);
                    if (Sfx_IsPlayingFromObject(0, (u16)((LargeCrateState*)state)->explodeSfxId) == 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((LargeCrateState*)state)->explodeSfxId);
                    }
                    ((LargeCrateState*)state)->breakTimer = 0x32;
                    ((LargeCrateState*)state)->damageTaken = 0;
                    largecrate_spawnDropContents(obj, player, state);
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
            }
            vec3f_distanceSquared(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
            if ((((LargeCrateState*)state)->idleTimer -= framesThisStep) <= 0)
            {
                ((LargeCrateState*)state)->idleTimer = (s16)(randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX) + LARGECRATE_RANDOM_DELAY_BASE);
            }
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                largecrate_updateConveyorSlide(obj, state);
            }
        }
    }
}

void largecrate_free(int obj)
{
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

void largecrate_init(int obj, u8* initData)
{
    int state;
    u32 r3rand;
    f32 fr;
    LargeCrateVariantRemap constArrA;
    LargeCrateVariantRemap constArrB;
    short id;

    constArrA = gLargeCrateVariantARemap;
    constArrB = gLargeCrateVariantBRemap;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = LargeCrate_SeqFn;
    ((GameObject*)obj)->anim.rotX = (short)((int)(signed char)initData[0x18] << 8);
    ((LargeCrateState*)state)->brokenGameBit = *(short*)(initData + 0x1e);

    id = *(short*)(initData + 0x1c);
    if (id == LARGECRATE_TIMER_SENTINEL_DISABLED)
    {
        ((LargeCrateState*)state)->breakTimeBonus = LARGECRATE_TIMER_SENTINEL_DISABLED;
    }
    else if (id == LARGECRATE_TIMER_SENTINEL_FOREVER)
    {
        ((LargeCrateState*)state)->breakTimeBonus = -1;
    }
    else
    {
        ((LargeCrateState*)state)->breakTimeBonus = id * LARGECRATE_TIMER_SCALE_FRAMES;
    }

    if (GameBit_Get((int)((LargeCrateState*)state)->brokenGameBit) != 0)
    {
        ((LargeCrateState*)state)->animTimer = lbl_803E39AC;
        ObjHits_DisableObject((u32)obj);
    }

    ((LargeCrateState*)state)->dropType = initData[0x19];
    lbl_803DDAC8 = Resource_Acquire(LARGECRATE_RESOURCE_ID, LARGECRATE_RESOURCE_MODE);
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX);
    ((LargeCrateState*)state)->idleTimer = (short)(r3rand + LARGECRATE_RANDOM_DELAY_BASE);
    ((LargeCrateState*)state)->unkC = LARGECRATE_DEFAULT_COUNTDOWN;
    ((LargeCrateState*)state)->unk12 = (u8) * (short*)(initData + 0x1a);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | LARGECRATE_OBJECT_FLAGS);
    ((GameObject*)obj)->anim.rotX = (short)((int)(signed char)initData[0x18] << 8);

    id = ((GameObject*)obj)->anim.seqId;
    if (id == LARGECRATE_VARIANT_A)
    {
        ((LargeCrateState*)state)->dropType = constArrA.entries[((LargeCrateState*)state)->dropType];
        ((LargeCrateState*)state)->hitSfxId = LARGECRATE_VARIANT_A_SFX_A;
        ((LargeCrateState*)state)->explodeSfxId = LARGECRATE_VARIANT_A_SFX_B;
    }
    else if (id == LARGECRATE_VARIANT_B || id == LARGECRATE_VARIANT_C)
    {
        ((LargeCrateState*)state)->dropType = constArrB.entries[((LargeCrateState*)state)->dropType];
        ((LargeCrateState*)state)->hitSfxId = LARGECRATE_VARIANT_B_SFX_A;
        ((LargeCrateState*)state)->explodeSfxId = LARGECRATE_VARIANT_B_SFX_B;
    }

    ((LargeCrateState*)state)->slideOffset = 0;
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_BOB_MAX);
    fr = (float)(int)r3rand;
    fr = lbl_803E39E8 + fr;
    ((LargeCrateState*)state)->slidePhase = fr;
    ((LargeCrateState*)state)->homeX = ((GameObject*)obj)->anim.localPosX;

    if (((GameObject*)obj)->anim.seqId == LARGECRATE_VARIANT_C)
    {
        ((LargeCrateState*)state)->damageThreshold = 0;
    }
    else
    {
        ((LargeCrateState*)state)->damageThreshold = 2;
    }
}

void largecrate_release(void)
{
}

void largecrate_initialise(void)
{
}
