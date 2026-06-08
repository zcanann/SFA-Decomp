#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/dll/dim_bossgut.h"
#include "main/dll/ediblemushroom.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a30();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern undefined4 FUN_80017a68();
extern int FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80081120();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern double FUN_80294c4c();
extern byte FUN_80294ca8();
extern int FUN_80294cb0();

extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e5fa0;
extern f64 DOUBLE_803e5fe0;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E5F90;
extern f32 lbl_803E5F94;
extern f32 lbl_803E5FB0;
extern f32 lbl_803E5FB4;
extern f32 lbl_803E5FB8;
extern f32 lbl_803E5FBC;
extern f32 lbl_803E5FC0;
extern f32 lbl_803E5FC4;
extern f32 lbl_803E5FC8;
extern f32 lbl_803E5FCC;
extern f32 lbl_803E5FD0;
extern f32 lbl_803E5FD4;
extern f32 lbl_803E5FD8;

/*

/*
 * --INFO--
 *
 * Function: enemymushroom_release
 * EN v1.0 Address: 0x801D2864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_release(void)
{
}

/*
 * --INFO--
 *
 * Function: enemymushroom_initialise
 * EN v1.0 Address: 0x801D2868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: bombplant_getExtraSize
 * EN v1.0 Address: 0x801D2B34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_getExtraSize(void)
{
  return 0x18;
}

/*
 * --INFO--
 *
 * Function: bombplant_getObjectTypeId
 * EN v1.0 Address: 0x801D2B3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: bombplant_free
 * EN v1.0 Address: 0x801D2B44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_free(void)
{
}

/*
 * --INFO--
 *
 * Function: bombplant_hitDetect
 * EN v1.0 Address: 0x801D2B6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_hitDetect(void)
{
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E5370;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void bombplant_render(void) { objRenderFn_8003b8f4(lbl_803E5370); }
#pragma peephole reset
#pragma scheduling reset

extern void *getTrickyObject(void);
extern void trickyImpress(void *trickyObj);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void fn_801D29E4(int *obj, int *p2);
extern f32 lbl_803E5378;
#pragma scheduling off
#pragma peephole off
void fn_801D2B70(int *obj, int unused, int *p3) {
    int *p4 = *(int **)&((GameObject *)obj)->anim.placementData;
    void *trickyObj = getTrickyObject();
    s16 gbId;
    int i;
    if (trickyObj != NULL) {
        trickyImpress(trickyObj);
    }
    Sfx_PlayFromObject(obj, SFXmv_curtainrustle);
    {
        int *p = *(int **)&((GameObject *)obj)->anim.hitReactState;
        *(s16 *)((char *)p + 0x60) = (s16)(*(s16 *)((char *)p + 0x60) | 0x40);
    }
    spawnExplosion((int)obj, lbl_803E5378, 0, 1, 1, 1, 0, 1, 0);
    *(u8 *)((char *)p3 + 0x14) = 1;
    *(u8 *)((char *)p3 + 0x15) = (u8)(*(u8 *)((char *)p3 + 0x15) | 2);
    gbId = *(s16 *)((char *)p4 + 0x1c);
    if (gbId != -1) {
        GameBit_Set(gbId, 0);
    } else {
        for (i = 0; i < 3; i++) {
            fn_801D29E4(obj, p3);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void ObjGroup_AddObject(int *obj, int group);
extern f32 lbl_803E52FC;
extern f32 lbl_803E5350;

/* EN v1.0 0x801D27B8  size: 172b  Mushroom enemy constructor: seeds the state
 * block, clamps the spin period, offsets the spawn height, flags the model,
 * optionally resets to spawn, and registers in object group 3. */
#pragma scheduling off
#pragma peephole off
void enemymushroom_init(EnemyMushroomObject *obj, EnemyMushroomMapData *arg, int flag)
{
    EnemyMushroomState *state = obj->state;
    f32 z = lbl_803E52FC;

    state->timer = z;
    state->hitRadius = z;
    state->baseScale = obj->scale;
    state->respawnFrameLimit = (s16)arg->respawnFrameLimit;
    if (state->respawnFrameLimit < 0x708) {
        state->respawnFrameLimit = 0x708;
    }
    obj->posY = arg->posY - lbl_803E5350;
    if (obj->modelState != NULL) {
        obj->modelState->flags |= 0x810;
    }
    if (flag == 0) {
        enemymushroom_resetToSpawn(obj, state, 0);
    }
    ObjGroup_AddObject((int *)obj, 3);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int a, int b);
extern void setMatrixFromObjectPos(void *mtx, void *build);
extern void Matrix_TransformPoint(void *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void Obj_SetupObject(int *obj, int a, int b, int c, int d);
extern f32 lbl_803E536C;
extern f32 lbl_803E5374;

typedef struct { s16 pos[3]; f32 w; f32 v[3]; } MushSpawnBuild;

/* EN v1.0 0x801D29E4  size: 336b  Spawns a spore object: builds a matrix from
 * the parent's grid pos, transforms a unit offset, and seeds the new object. */
#pragma scheduling off
#pragma peephole off
void fn_801D29E4(int *obj, int *p2)
{
    int *spore;
    int *base = *(int **)&((GameObject *)obj)->anim.placementData;

    if (Obj_IsLoadingLocked()) {
        MushSpawnBuild bd;
        f32 mtx[4][4];
        f32 tz, ty, tx;
        f32 sx;

        spore = Obj_AllocObjectSetup(0x24, 0x198);
        bd.pos[0] = ((GameObject *)obj)->anim.rotX;
        bd.pos[1] = ((GameObject *)obj)->anim.rotY;
        bd.pos[2] = ((GameObject *)obj)->anim.rotZ;
        bd.v[0] = lbl_803E536C;
        bd.v[1] = lbl_803E536C;
        bd.v[2] = lbl_803E536C;
        bd.w = lbl_803E5370;
        setMatrixFromObjectPos(mtx, &bd);
        Matrix_TransformPoint(mtx, lbl_803E536C, lbl_803E5370, lbl_803E536C, &tx, &ty, &tz);
        sx = lbl_803E5374 * tx;
        bd.v[0] = sx;
        bd.v[1] = lbl_803E5374 * ty;
        bd.v[2] = lbl_803E5374 * tz;
        *(f32 *)((char *)spore + 0x8)  = ((GameObject *)obj)->anim.localPosX + sx;
        *(f32 *)((char *)spore + 0xc)  = ((GameObject *)obj)->anim.localPosY + bd.v[1];
        *(f32 *)((char *)spore + 0x10) = ((GameObject *)obj)->anim.localPosZ + bd.v[2];
        *(u8 *)((char *)spore + 0x5) = 1;
        *(u8 *)((char *)spore + 0x4) = 2;
        *(s16 *)((char *)spore + 0x1a) = (s16)((s8)*(s8 *)((char *)base + 0x1e) << 8);
        *(s16 *)((char *)spore + 0x1c) = ((GameObject *)obj)->anim.rotX;
        Obj_SetupObject(spore, 5, -1, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_KeepAliveLoopedObjectSound(int *obj, int id);
extern void ObjHits_RefreshObjectState(int *obj);
extern EffectInterface **gPartfxInterface;
extern f32 lbl_803E5358;
extern f32 lbl_803E535C;

/* EN v1.0 0x801D286C  size: 376b  Bombplant per-tick sequencer: on the armed
 * frame snaps the model to the spawn pose and refreshes hits; otherwise keeps
 * the loop sfx alive, jitters the fuse, and fires the spark particle. */
#pragma scheduling off
#pragma peephole off
int bombplant_SeqFn(int *obj)
{
    float *state = ((GameObject *)obj)->extra;

    if (*(u8 *)((char *)state + 0x14) != 0) {
        int *src;
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        src = *(int **)&((GameObject *)obj)->anim.placementData;
        ((GameObject *)obj)->anim.alpha = 0xff;
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        ((GameObject *)obj)->anim.localPosX  = *(f32 *)((char *)src + 0x8);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)((char *)src + 0xc);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)((char *)src + 0x10);
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E5358;
        *(f32 *)((char *)state + 0x8) = lbl_803E535C;
        *(f32 *)((char *)state + 0x4) = *(f32 *)((char *)state + 0xc);
        *(f32 *)((char *)state + 0x10) = *(f32 *)((char *)state + 0x4) / *(f32 *)((char *)state + 0x8);
        *(f32 *)((char *)state + 0x0) = *(f32 *)((char *)state + 0x8);
        ObjHits_RefreshObjectState(obj);
        *(u8 *)((char *)state + 0x14) = 0;
        *(u8 *)((char *)state + 0x15) = (u8)(*(u8 *)((char *)state + 0x15) | 2);
    } else {
        int *base;
        u8 flags;
        Sfx_KeepAliveLoopedObjectSound(obj, 0x3fd);
        base = *(int **)&((GameObject *)obj)->anim.placementData;
        flags = *(u8 *)((char *)state + 0x15);
        if (flags & 0x2) {
            int v;
            *(u8 *)((char *)state + 0x15) = (u8)(flags & ~0x2);
            v = *(s16 *)((char *)base + 0x1a) + randomGetRange(-0x32, 0x32);
            *(f32 *)((char *)state + 0x0) = (f32)v;
        }
        if (((GameObject *)obj)->objectFlags & 0x800) {
            (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int  objIsFrozen(int *obj);
extern f32  Vec_distance(f32 *a, f32 *b);
extern int  EmissionController_IsLingering(u8 *player);
extern int  fn_80296448(u8 *player);
extern f32  fn_8029610C(u8 *player);
extern void objFn_8002b67c(int *obj);
extern void Obj_StartModelFadeIn(int *obj, int frames);
extern void Obj_ResetModelColorState(int *obj);
extern void objLightFn_8009a1dc(int *obj, f32 a, void *vec, int b, int c);
extern int  Sfx_PlayFromObject(int *obj, int id);
extern f32  sqrtf(f32 x);
extern u8   framesThisStep;
extern f32  timeDelta;
extern f32  playerMapOffsetX;
extern f32  playerMapOffsetZ;
extern s16  lbl_80326C78[];
extern f32  lbl_80326C90[];
extern f32  lbl_803E52F8;
extern f32  lbl_803E5314;
extern f32  lbl_803E5318;
extern f32  lbl_803E531C;
extern f32  lbl_803E5320;
extern f32  lbl_803E5324;
extern f32  lbl_803E5328;
extern f32  lbl_803E532C;
extern f32  lbl_803E5330;
extern f32  lbl_803E5334;
extern f32  lbl_803E5338;
extern f32  lbl_803E533C;
extern f32  lbl_803E5340;

typedef struct { f32 unk[3]; f32 x, y, z; } MushHitInfo;

/* EN v1.0 0x801D1E24  size: 2452b  Mushroom enemy state machine: dormant ->
 * inflate -> chase -> deflate cycle, hit reaction, pop and respawn. */
#pragma scheduling off
#pragma peephole off
void enemymushroom_update(int *obj)
{
    char *state = ((GameObject *)obj)->extra;
    u8 *player;
    int *src;
    MushHitInfo hv;
    f32 o1, o2, o3;
    int hitType;

    player = (u8 *)Obj_GetPlayerObject();
    src = *(int **)&((GameObject *)obj)->anim.placementData;
    ObjHits_ClearHitVolumes(obj);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
    *(u8 *)(state + 0x37) |= 0x4;

    if (objIsFrozen(obj)) {
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &o1, &o2, &o3, &hv.x, &hv.y, &hv.z);
        if (hitType != 0 && hitType != 0x10) {
            hv.x += playerMapOffsetX;
            hv.z += playerMapOffsetZ;
            objLightFn_8009a1dc(obj, lbl_803E5314, &hv, 1, 0);
            Sfx_PlayFromObject(obj, 0x47b);
            Obj_ResetModelColorState(obj);
        }
        return;
    }

    if (*(u16 *)(player + 0xb0) & 0x1000) {
        return;
    }

    switch (*(u8 *)(state + 0x36)) {
    case 6:
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9a);
        *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x6);
        *(f32 *)(state + 0x2c) = lbl_803E5318 * timeDelta + *(f32 *)(state + 0x2c);
        if (*(f32 *)(state + 0x2c) > lbl_803E531C) {
            *(f32 *)(state + 0x2c) = lbl_803E531C;
        }
        if (!(*(u8 *)(state + 0x37) & 0x1)) {
            if (Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(player + 0x18)) <= *(f32 *)(state + 0x2c) &&
                !EmissionController_IsLingering(player) && !fn_80296448(player) &&
                !(*(u16 *)(player + 0xb0) & 0x1000)) {
                ObjHits_RecordObjectHit(player, obj, 0x16, 1, 0);
                *(u8 *)(state + 0x37) |= 0x1;
            }
        }
        if (*(u8 *)(state + 0x37) & 0x2) {
            *(f32 *)(state + 0x0) = lbl_803E52FC;
            *(u8 *)(state + 0x36) = 2;
        }
        hv.x = *(f32 *)(state + 0x20);
        hv.y = *(f32 *)(state + 0x24);
        hv.z = *(f32 *)(state + 0x28);
        {
            u8 k = 1;
            int base = 0x200000;
            while (k != 0) {
                (*gPartfxInterface)->spawnObject(obj, 0x3eb, &hv, base + 1,
                                                                    -1, NULL);
                k--;
            }
        }
        break;
    case 2:
        *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x6);
        if (*(u8 *)(state + 0x37) & 0x2) {
            int t = ((GameObject *)obj)->anim.alpha - framesThisStep * 4;
            if (t < 0) {
                t = 0;
            }
            ((GameObject *)obj)->anim.alpha = (u8)t;
            *(f32 *)(state + 0x0) = *(f32 *)(state + 0x0) + timeDelta;
            if (*(f32 *)(state + 0x0) > (f32)*(s16 *)(state + 0x34)) {
                enemymushroom_resetToSpawn((EnemyMushroomObject *)obj, (EnemyMushroomState *)state, 1);
                *(u8 *)(state + 0x36) = 1;
            }
        }
        break;
    case 3:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9c);
        if (*(u8 *)(state + 0x37) & 0x2) {
            *(u8 *)(state + 0x36) = 4;
        }
        break;
    case 4:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
        *(f32 *)(state + 0x2c) = lbl_803E5320 * timeDelta + *(f32 *)(state + 0x2c);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9a);
        if (!(*(u8 *)(state + 0x37) & 0x1)) {
            if (Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(player + 0x18)) <= *(f32 *)(state + 0x2c) &&
                !EmissionController_IsLingering(player) && !fn_80296448(player) &&
                !(*(u16 *)(player + 0xb0) & 0x1000)) {
                ObjHits_RecordObjectHit(player, obj, 0x16, 1, 0);
                *(u8 *)(state + 0x37) |= 0x1;
            }
        }
        if (*(f32 *)(state + 0x2c) > lbl_803E531C) {
            *(f32 *)(state + 0x2c) = lbl_803E531C;
        }
        *(f32 *)(state + 0x0) = *(f32 *)(state + 0x0) + timeDelta;
        if (*(f32 *)(state + 0x0) > lbl_803E5324) {
            *(f32 *)(state + 0x0) = lbl_803E52FC;
            *(u8 *)(state + 0x36) = 5;
        }
        hv.x = *(f32 *)(state + 0x20);
        hv.y = *(f32 *)(state + 0x24);
        hv.z = *(f32 *)(state + 0x28);
        {
            u8 k = 1;
            int base = 0x200000;
            while (k != 0) {
                (*gPartfxInterface)->spawnObject(obj, 0x3eb, &hv, base + 1,
                                                                    -1, NULL);
                k--;
            }
        }
        break;
    case 5:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
        *(f32 *)(state + 0x0) = *(f32 *)(state + 0x0) + timeDelta;
        if (*(f32 *)(state + 0x0) > (f32)*(u16 *)((char *)src + 0x18)) {
            if (*(u8 *)(state + 0x37) & 0x2) {
                *(u8 *)(state + 0x36) = 0;
                *(f32 *)(state + 0x2c) = lbl_803E52FC;
                *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x1);
            }
        }
        break;
    case 1:
        *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x6);
        if (((GameObject *)obj)->anim.rootMotionScale > *(f32 *)(state + 0x4)) {
            *(f32 *)(state + 0x10) = *(f32 *)(state + 0x10) / lbl_803E5328;
        }
        if (*(f32 *)(state + 0x10) < lbl_803E52F8) {
            *(f32 *)(state + 0x10) = lbl_803E52FC;
        }
        *(f32 *)(state + 0x0) = *(f32 *)(state + 0x0) + timeDelta;
        ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(state + 0x10) * timeDelta + ((GameObject *)obj)->anim.rootMotionScale;
        if (*(f32 *)(state + 0x0) > *(f32 *)(state + 0x8)) {
            *(u8 *)(state + 0x36) = 0;
        }
        break;
    case 9:
        if (*(f32 *)(state + 0x0) <= lbl_803E52FC) {
            *(f32 *)(state + 0x0) = (f32)(int)randomGetRange(0xf0, 0x12c);
        }
        if (*(u8 *)(state + 0x37) & 0x2) {
            *(f32 *)(state + 0x0) = lbl_803E52FC;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9b);
        {
            f32 nv = *(f32 *)(state + 0x0) - timeDelta;
            *(f32 *)(state + 0x0) = nv;
            if (nv <= lbl_803E52FC) {
                (*gExpgfxInterface)->freeSource((u32)obj);
                *(u8 *)(state + 0x36) = 0;
                objFn_8002b67c(obj);
            } else {
                f32 nw = *(f32 *)(state + 0x30) - timeDelta;
                *(f32 *)(state + 0x30) = nw;
                if (nw <= lbl_803E52FC) {
                    hv.x = lbl_803E532C;
                    hv.y = lbl_803E5330;
                    (*gPartfxInterface)->spawnObject(obj, 0x51d, &hv, 2, -1,
                                                                        NULL);
                    *(f32 *)(state + 0x30) = lbl_803E5334;
                }
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
            }
        }
        break;
    case 0xa:
        ObjHits_DisableObject(obj);
        *(f32 *)(state + 0x0) = *(f32 *)(state + 0x0) + timeDelta;
        if (*(f32 *)(state + 0x0) > (f32)*(s16 *)(state + 0x34)) {
            enemymushroom_resetToSpawn((EnemyMushroomObject *)obj, (EnemyMushroomState *)state, 1);
            *(u8 *)(state + 0x36) = 1;
            objFn_8002b67c(obj);
        }
        break;
    default:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
        {
            f32 dx = *(f32 *)(player + 0xc) - ((GameObject *)obj)->anim.localPosX;
            f32 dy = *(f32 *)(player + 0x10) - ((GameObject *)obj)->anim.localPosY;
            f32 dz = *(f32 *)(player + 0x14) - ((GameObject *)obj)->anim.localPosZ;
            if ((u16)(int)sqrtf(dx * dx + dy * dy + dz * dz) <
                (u16)(int)(lbl_803E5338 * (f32)*(u8 *)((char *)src + 0x1e))) {
                if (fn_8029610C(player) >= lbl_803E533C) {
                    *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x1);
                    *(u8 *)(state + 0x36) = 3;
                    *(f32 *)(state + 0x0) = lbl_803E52FC;
                    Sfx_PlayFromObject(obj, 0x48e);
                }
            }
        }
        break;
    }

    hitType = ObjHits_GetPriorityHitWithPosition(obj, &o1, &o2, &o3, &hv.x, &hv.y, &hv.z);
    hv.x += playerMapOffsetX;
    hv.z += playerMapOffsetZ;
    if (hitType != 0) {
        if (*(u8 *)(state + 0x37) & 0x4) {
            if (hitType == 0x10) {
                Obj_StartModelFadeIn(obj, 0x12c);
            } else {
                if (*(u8 *)(state + 0x36) != 9) {
                    Sfx_PlayFromObject(obj, 0x9d);
                }
                *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x1);
                if (*(s16 *)((char *)src + 0x1c) != -1) {
                    GameBit_Set(*(s16 *)((char *)src + 0x1c), 1);
                }
                *(u8 *)(state + 0x36) = 9;
                *(f32 *)(state + 0x0) = lbl_803E52FC;
                ((GameObject *)obj)->anim.currentMoveProgress = (f32)(int)randomGetRange(0, 0x28) / lbl_803E5340;
            }
            objLightFn_8009a1dc(obj, lbl_803E5314, &hv, 1, 0);
        }
    }

    if (((GameObject *)obj)->anim.currentMove != lbl_80326C78[*(u8 *)(state + 0x36)]) {
        ObjAnim_SetCurrentMove((int)obj, lbl_80326C78[*(u8 *)(state + 0x36)], lbl_803E52FC, 0);
    }
    if (ObjAnim_AdvanceCurrentMove(lbl_80326C90[*(u8 *)(state + 0x36)], timeDelta,
                                   (int)obj, NULL) != 0) {
        *(u8 *)(state + 0x37) |= 0x2;
    } else {
        *(u8 *)(state + 0x37) = (u8)(*(u8 *)(state + 0x37) & ~0x2);
    }
}
#pragma peephole reset
#pragma scheduling reset
