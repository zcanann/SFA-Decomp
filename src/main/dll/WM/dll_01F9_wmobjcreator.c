/*
 * WM_ObjCreator (DLL 0x1F9) - the ambient-object spawner at Krazoa
 * Palace (map 'warlock'). TU: 0x801EF360-0x801EFF7C.
 *
 * Each placed instance runs one spawnMode: a one-shot WM_Galleon or
 * HoodedZyck, periodic LFXEmitter ambience (drifting leaves/petals in
 * several configurations), the cut WM_WallCraw enemy, or a falling
 * WM_rock with a debris-particle burst. Periodic modes rearm
 * spawnTimer from spawnPeriod + randomGetRange(0, spawnJitter); most
 * modes gate on the placement game bit (-1 = always).
 */
#include "main/effect_interfaces.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"


extern int lbl_803DDC68; /* live WM_WallCraw population counter */
extern const f32 lbl_803E5CC8; /* 1.0 */
extern f32 lbl_803E5CCC; /* 10.0: eastward drift base velocity */
extern f32 lbl_803E5CD0; /* -30.0: westward drift base velocity */
extern f32 lbl_803E5CD4; /* 0.1: burst velocity scale */
extern const f32 lbl_803E5CD8; /* 0.0 */
extern const f32 lbl_803E5CDC; /* 200.0 */

/* romlist object types this creator spawns (names from the retail
   OBJECTS.bin; the handling DLL ids confirm the targets). */
enum
{
    WMOBJCREATOR_SPAWN_WM_GALLEON = 0x139,     /* dll 0x1F8 wmgalleon */
    WMOBJCREATOR_SPAWN_LFX_EMITTER = 0x263,    /* dll 0x12D lfxemitter */
    WMOBJCREATOR_SPAWN_WM_WALLCRAWLER = 0x275, /* dll 0x211 wmwallcrawler */
    WMOBJCREATOR_SPAWN_HOODED_ZYCK = 0x4AC,    /* dll 0x0C9 enemy */
    WMOBJCREATOR_SPAWN_WM_ROCK = 0x2BC         /* dll 0x12A */
};

/* gate for the galleon spawn: set once the palace approach has run */
#define GAMEBIT_WM_GALLEON_GONE 0x78

int WM_ObjCreator_getExtraSize(void) { return 0x8; }
int WM_ObjCreator_getObjectTypeId(void) { return 0x0; }

void WM_ObjCreator_free(void)
{
}

void WM_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5CC8);
}

void WM_ObjCreator_hitDetect(void)
{
}

/* WM_ObjCreator per-object extra state (four s16 slots). */
typedef struct WmObjCreatorState
{
    s16 gameBit; /* 0x00: spawn gate, -1 = always */
    s16 spawnPeriod; /* 0x02 */
    s16 spawnTimer; /* 0x04 */
    s16 spawnJitter; /* 0x06: randomGetRange(0, jitter) added per cycle */
} WmObjCreatorState;

STATIC_ASSERT(sizeof(WmObjCreatorState) == 0x8);

typedef struct WmObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnPeriod;
    s8 yaw;
    s8 spawnJitter;
    u8 pad20[4];
} WmObjCreatorPlacement;

STATIC_ASSERT(offsetof(WmObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(WmObjCreatorPlacement, spawnJitter) == 0x1F);
STATIC_ASSERT(sizeof(WmObjCreatorPlacement) == 0x24);

/* The creator-written slices of the spawned types' placement records
   (field meanings belong to the handling DLLs; unknown slots keep
   honest unkNN names). */
typedef struct WmGalleonSpawnSetup
{
    ObjPlacement base;
    s8 yawByte; /* 0x18: rotY in 1/256 turns */
    u8 pad19;
    s16 unk1A; /* 0x1A: 2 */
    u8 pad1C[2];
    s16 unk1E; /* 0x1E: -1 */
} WmGalleonSpawnSetup;

STATIC_ASSERT(offsetof(WmGalleonSpawnSetup, unk1E) == 0x1E);

typedef struct WmRockSpawnSetup
{
    ObjPlacement base;
    s8 yawByte; /* 0x18: creator's own rotX high byte */
    u8 pad19[5];
    s16 unk1E; /* 0x1E: -1 */
} WmRockSpawnSetup;

STATIC_ASSERT(offsetof(WmRockSpawnSetup, unk1E) == 0x1E);

typedef struct HoodedZyckSpawnSetup
{
    ObjPlacement base;
    s16 triggerGameBit; /* 0x18: the creator's own gate bit, handed on */
    u8 pad1A[8];
    s16 unk22; /* 0x22: 1 */
    u8 pad24[6];
    s8 yawByte; /* 0x2A: random heading */
} HoodedZyckSpawnSetup;

STATIC_ASSERT(offsetof(HoodedZyckSpawnSetup, yawByte) == 0x2A);

/* mirror of WmwallcrawlerMapData (dll_0211_wmwallcrawler.c) */
typedef struct WmWallcrawlerSpawnSetup
{
    ObjPlacement base;
    s8 rotXByte;       /* 0x18 */
    u8 variant;        /* 0x19 */
    s16 triggerRadius; /* 0x1A */
    s16 heightOffset;  /* 0x1C */
} WmWallcrawlerSpawnSetup;

STATIC_ASSERT(offsetof(WmWallcrawlerSpawnSetup, heightOffset) == 0x1C);

void WM_ObjCreator_update(int obj)
{
    extern void* ObjGroup_GetObjects(); /* #57 */
    /* setup/spawned/n are FN-SCOPE on purpose: live-range splitting
       re-creates per-arm webs in the retail saved-reg spread, where
       block locals coalesce (#108 crack; case 1 and case 4's setup
       really were block-scope - see below). */
    int setup;
    int spawned;
    int n;
    WmObjCreatorPlacement* placement;
    WmObjCreatorState* state;
    int count;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4]; /* [0] scale, [1] velX, [2] velY, [3] velZ */
    } vec;

    placement = (WmObjCreatorPlacement*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        switch (placement->spawnMode)
        {
        case 0: /* one-shot WM_Galleon at the placement, at most one alive */
            {
                int* objs;
                int k;
                /* dead-on-this-path state recycled as the spawn-ok flag
                   (#119: lands the flag web in state's r29 = retail) */
                state = (WmObjCreatorState*)0;
                if (((GameObject*)obj)->unkF8 == 0)
                {
                    state = (WmObjCreatorState*)1;
                    if (GameBit_Get(GAMEBIT_WM_GALLEON_GONE) != 0)
                    {
                        state = (WmObjCreatorState*)0;
                    }
                    objs = ObjGroup_GetObjects(3, &count);
                    k = 0;
                    while (k < count && (s8)(int)state)
                    {
                        if (((GameObject*)*objs)->anim.seqId == WMOBJCREATOR_SPAWN_WM_GALLEON)
                        {
                            state = (WmObjCreatorState*)0;
                        }
                        objs += 1;
                        k += 1;
                    }
                }
                if ((s8)(int)state)
                {
                    setup = Obj_AllocObjectSetup(0x24, WMOBJCREATOR_SPAWN_WM_GALLEON);
                    ((ObjPlacement*)setup)->posX = placement->base.posX;
                    ((ObjPlacement*)setup)->posY = placement->base.posY;
                    ((ObjPlacement*)setup)->posZ = placement->base.posZ;
                    ((ObjPlacement*)setup)->color[0] = placement->base.color[0];
                    ((ObjPlacement*)setup)->color[1] = placement->base.color[1];
                    ((ObjPlacement*)setup)->color[2] = placement->base.color[2];
                    ((ObjPlacement*)setup)->color[3] = placement->base.color[3];
                    ((WmGalleonSpawnSetup*)setup)->unk1E = 0xffff;
                    ((WmGalleonSpawnSetup*)setup)->unk1A = 2;
                    ((WmGalleonSpawnSetup*)setup)->yawByte = placement->yaw;
                    spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                              *(int*)&((GameObject*)obj)->anim.parent);
                    if ((u32)spawned != 0)
                    {
                        ((GameObject*)spawned)->unkF4 = 8;
                    }
                    ((GameObject*)obj)->unkF8 = 1;
                }
                break;
            }
        case 1: /* periodic LFXEmitter at the creator, drifting east */
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                int setup = Obj_AllocObjectSetup(LFXEMITTER_PLACEMENT_BYTES,
                                                 WMOBJCREATOR_SPAWN_LFX_EMITTER);
                ((ObjPlacement*)setup)->color[0] = 0x20;
                ((ObjPlacement*)setup)->color[1] = 2;
                ((ObjPlacement*)setup)->color[3] = 0xff;
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                ((LfxEmitterPlacement*)setup)->lifeTimer = 0x50;
                ((LfxEmitterPlacement*)setup)->configIndex = 0x10f;
                ((LfxEmitterPlacement*)setup)->enableBit = 0xffff;
                ((LfxEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LfxEmitterPlacement*)setup)->spinPitch = 0;
                ((LfxEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    ((GameObject*)spawned)->anim.velocityX = lbl_803E5CCC + (f32)(int)randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 5: /* periodic WM_WallCraw near the creator (cut content) */
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x24, WMOBJCREATOR_SPAWN_WM_WALLCRAWLER);
                ((WmWallcrawlerSpawnSetup*)setup)->rotXByte = randomGetRange(-0x7f, 0x7e);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)randomGetRange(-100, 100);
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)randomGetRange(-100, 100);
                ((WmWallcrawlerSpawnSetup*)setup)->triggerRadius = 0x31;
                ((WmWallcrawlerSpawnSetup*)setup)->heightOffset = 200;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    lbl_803DDC68 += 1;
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 8: /* one-shot HoodedZyck on the gate bit (bit is consumed) */
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(0x38, WMOBJCREATOR_SPAWN_HOODED_ZYCK);
                GameBit_Set(state->gameBit, 0);
                ((HoodedZyckSpawnSetup*)setup)->yawByte = randomGetRange(-0x7f, 0x7e);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                ((HoodedZyckSpawnSetup*)setup)->triggerGameBit = state->gameBit;
                ((HoodedZyckSpawnSetup*)setup)->unk22 = 1;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1c3, NULL, 2, -1, NULL);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 2: /* periodic LFXEmitter at the placement, drifting west */
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(LFXEMITTER_PLACEMENT_BYTES,
                                             WMOBJCREATOR_SPAWN_LFX_EMITTER);
                ((ObjPlacement*)setup)->color[0] = 4;
                ((ObjPlacement*)setup)->color[1] = 2;
                ((ObjPlacement*)setup)->posX = placement->base.posX;
                ((ObjPlacement*)setup)->posY = placement->base.posY + (f32)(int)randomGetRange(-0x28, 0x28);
                ((ObjPlacement*)setup)->posZ = placement->base.posZ + (f32)(int)randomGetRange(-0x28, 0x28);
                ((LfxEmitterPlacement*)setup)->lifeTimer = 100;
                ((LfxEmitterPlacement*)setup)->configIndex = 0x10f;
                ((LfxEmitterPlacement*)setup)->enableBit = 0xffff;
                ((LfxEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LfxEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                          *(int*)&((GameObject*)obj)->anim.parent);
                if ((u32)spawned != 0)
                {
                    ((GameObject*)spawned)->anim.velocityX = lbl_803E5CD0 - (f32)(int)randomGetRange(0, 10);
                }
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 4: /* two scattering LFXEmitters on the gate bit, with an
                   attached particle trail each (bit is consumed) */
            if (GameBit_Get(state->gameBit) != 0 || state->gameBit == -1)
            {
                n = 2;
                do
                {
                    int setup;
                    n -= 1;
                    setup = Obj_AllocObjectSetup(LFXEMITTER_PLACEMENT_BYTES,
                                                 WMOBJCREATOR_SPAWN_LFX_EMITTER);
                    ((ObjPlacement*)setup)->color[0] = 0x20;
                    ((ObjPlacement*)setup)->color[1] = 2;
                    ((ObjPlacement*)setup)->color[3] = 0xff;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                    ((LfxEmitterPlacement*)setup)->lifeTimer = 400;
                    ((LfxEmitterPlacement*)setup)->configIndex = 0xf;
                    ((LfxEmitterPlacement*)setup)->enableBit = 0x222;
                    ((LfxEmitterPlacement*)setup)->spinRoll = 0;
                    ((LfxEmitterPlacement*)setup)->spinPitch = 0;
                    ((LfxEmitterPlacement*)setup)->spinYaw = 0;
                    ((LfxEmitterPlacement*)setup)->followCurve = 0;
                    spawned = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                              *(int*)&((GameObject*)obj)->anim.parent);
                    if ((u32)spawned != 0)
                    {
                        *(u8*)(*(int*)&((GameObject*)spawned)->extra + 0x120) |= 2;
                        ((GameObject*)spawned)->anim.velocityX = lbl_803E5CD4 * (f32)(int)randomGetRange(-0x23, 0x23);
                        ((GameObject*)spawned)->anim.velocityZ = lbl_803E5CD4 * (f32)(int)randomGetRange(-0x23, 0x23);
                        ((GameObject*)spawned)->anim.velocityY = lbl_803E5CD8;
                        vec.pos[0] = lbl_803E5CC8;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = ((GameObject*)spawned)->anim.velocityX;
                        vec.pos[3] = ((GameObject*)spawned)->anim.velocityZ;
                        vec.pos[2] = lbl_803E5CD8;
                        (*gPartfxInterface)->spawnObject((void*)spawned, 0x1a7, &vec,
                                                         0x10000, -1, NULL);
                    }
                }
                while (n != 0);
                GameBit_Set(state->gameBit, 0);
            }
            break;
        case 7: /* periodic LFXEmitter around the placement, random config */
            if ((GameBit_Get(state->gameBit) != 0 || state->gameBit == -1) &&
                (state->spawnTimer -= framesThisStep, state->spawnTimer <= 0))
            {
                setup = Obj_AllocObjectSetup(LFXEMITTER_PLACEMENT_BYTES,
                                             WMOBJCREATOR_SPAWN_LFX_EMITTER);
                ((ObjPlacement*)setup)->color[0] = 4;
                ((ObjPlacement*)setup)->color[1] = 2;
                ((ObjPlacement*)setup)->posX = placement->base.posX + (f32)(int)randomGetRange(-0x28, 0x28);
                ((ObjPlacement*)setup)->posY = placement->base.posY + (f32)(int)randomGetRange(0, 0x14);
                ((ObjPlacement*)setup)->posZ = placement->base.posZ + (f32)(int)randomGetRange(-0x28, 0x28);
                ((LfxEmitterPlacement*)setup)->lifeTimer = 0x1c2;
                ((LfxEmitterPlacement*)setup)->configIndex = randomGetRange(0, 2) + 0x1cc;
                ((LfxEmitterPlacement*)setup)->enableBit = 0xffff;
                ((LfxEmitterPlacement*)setup)->spinRoll = randomGetRange(-500, 500) + 0x5dc;
                ((LfxEmitterPlacement*)setup)->spinYaw = randomGetRange(-500, 500) + 0x5dc;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
                state->spawnTimer = state->spawnPeriod + randomGetRange(0, state->spawnJitter);
            }
            break;
        case 6: /* falling WM_rock above the creator + a debris-particle
                   burst (bit is consumed) */
            if (GameBit_Get(state->gameBit) != 0 || state->gameBit == -1)
            {
                setup = Obj_AllocObjectSetup(0x24, WMOBJCREATOR_SPAWN_WM_ROCK);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)randomGetRange(-0x104, 0x104);
                ((ObjPlacement*)setup)->posY = lbl_803E5CDC + ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)randomGetRange(-0x50, 0x50);
                ((ObjPlacement*)setup)->color[0] = 0x20;
                ((ObjPlacement*)setup)->color[1] = 2;
                ((ObjPlacement*)setup)->color[3] = 0xff;
                ((WmRockSpawnSetup*)setup)->unk1E = 0xffff;
                ((WmRockSpawnSetup*)setup)->yawByte = ((GameObject*)obj)->anim.rotX >> 8;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
                for (n = randomGetRange(2, 5); n != 0; n -= 1)
                {
                    vec.pos[0] = lbl_803E5CC8;
                    vec.dir[0] = 0;
                    vec.dir[1] = 0;
                    vec.dir[2] = 0;
                    vec.pos[1] = (f32)(int)randomGetRange(-200, 200);
                    vec.pos[3] = (f32)(int)randomGetRange(-0x14, 0x14);
                    vec.pos[2] = lbl_803E5CDC;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1a6, &vec, 0x10002, -1,
                                                     NULL);
                }
                GameBit_Set(state->gameBit, 0);
            }
            break;
        }
    }
}

void WM_ObjCreator_init(int* obj, s8* def)
{
    WmObjCreatorPlacement* placement = (WmObjCreatorPlacement*)def;
    WmObjCreatorState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)placement->yaw << 8);
    state->gameBit = placement->gameBit;
    state->spawnPeriod = placement->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->spawnJitter = (s16)(s32)placement->spawnJitter;
}

void WM_ObjCreator_release(void)
{
}

void WM_ObjCreator_initialise(void)
{
}
