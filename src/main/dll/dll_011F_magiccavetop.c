/* DLL 0x011F (magiccavetop) — Magic Cave top area objects [0x8018AFC8-0x8018B7B0). */
#include "main/objseq.h"
extern void* Obj_GetPlayerObject(void);
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/player_objects.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define MAGICCAVETOP_OBJFLAG_HIDDEN 0x4000
#define MAGICCAVETOP_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MAGICCAVE_GAMEBIT_WARP_READY 0x91e   /* handoff from bottom: perform warp sequence */
#define MAGICCAVE_GAMEBIT_WARP_DEST 0x1b8    /* warp destination map index */
#define MAGICCAVETOP_GAMEBIT_SLOT_D_CLEAR 0xe05 /* cleared when arriving via map slot 0xd */

#define MAGICCAVETOP_SUBSTATE_IDLE 0     /* waiting for player to approach; load map on entry */
#define MAGICCAVETOP_SUBSTATE_LOADED 1   /* map loaded/active; unload on exit or start warp sequence */
#define MAGICCAVETOP_SUBSTATE_WARPING 2  /* running warp sequence: set dest, lock levels, warpToMap */
#define MAGICCAVETOP_SUBSTATE_WARP_DONE 3 /* warp handoff complete; wait for player to leave */

typedef struct MagiccavetopPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 rangeOuter;
    u8 rangeInner;
    u8 objGroup;
    u8 mapAct;
    s16 visibleGameBit;
    u8 lockDirId;
    u8 mapId;
    s8 warpMapId;
    s8 gameBitValue; /* value written to game bit 0x1B8 on warp transition */
    u8 noLoad;
    u8 rotByte;
    u8 pad24[0x28 - 0x24];
} MagiccavetopPlacement;

typedef struct MagiccavetopObjectDef
{
    u8 pad0[0x1C - 0x0];
    s16 visibleGameBit;
    u8 pad1E[0x23 - 0x1E];
    u8 rotByte;
    s16 swapGameBit;
    u8 pad26[0x28 - 0x26];
} MagiccavetopObjectDef;

typedef struct MagiccavetopState
{
    u8 subState;
    u8 flags;
    u8 rumbleState;
    u8 pad3[0x4 - 0x3];
    f32 fadeTimer;
    f32 timer;
} MagiccavetopState;

extern f32 timeDelta;
extern int Obj_GetActiveModel(int* obj);
extern int* ObjModel_GetRenderOpTextureRefs(int model, int idx);
extern f32 gMagicCaveTopFadeMax;

extern void staffSetGlow(void* a, int b, int c);



extern f32 vec3f_distanceSquared(f32* a, f32* b);



extern void stopRumble(void);

extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void objfx_spawnArcedBurst(int* obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 sx, f32 sy, f32 sz,
                                  void* args, int a);
extern f32 gMagicCaveTopWarpDistSq;
extern f32 gMagicCaveTopRumbleStartDistSq;
extern f32 lbl_803E3C38;
extern f32 gMagicCaveTopRumbleStopDistSq;
extern f32 gMagicCaveTopRumblePulseDistSq;
extern f32 gMagicCaveTopRumbleStrength;
extern f32 gMagicCaveTopRumbleDuration;
extern f32 gMagicCaveTopAlphaMax;
extern f32 gMagicCaveTopBurstHeight1;
extern f32 gMagicCaveTopBurstRadius;
extern f32 gMagicCaveTopBurstSpreadX;
extern f32 gMagicCaveTopBurstSpreadY;
extern f32 gMagicCaveTopBurstSpreadZ;
extern f32 gMagicCaveTopBurstHeight2;

int magiccavetop_getExtraSize(void) { return 0xc; }

void magiccavetop_init(int* obj, s8* def)
{
    MagiccavetopState* state = ((GameObject*)obj)->extra;
    int* refs;
    ((GameObject*)obj)->objectFlags = (u16)((u32)((GameObject*)obj)->objectFlags | (MAGICCAVETOP_OBJFLAG_HIDDEN | MAGICCAVETOP_OBJFLAG_HITDETECT_DISABLED));
    if (GameBit_Get(((MagiccavetopObjectDef*)def)->visibleGameBit) != 0)
    {
        state->fadeTimer = gMagicCaveTopFadeMax;
    }
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(u8)((MagiccavetopObjectDef*)def)->rotByte << 8);
    refs = ObjModel_GetRenderOpTextureRefs(Obj_GetActiveModel(obj), 0);
    if (((MagiccavetopObjectDef*)def)->swapGameBit > 0)
    {
        if (GameBit_Get(((MagiccavetopObjectDef*)def)->swapGameBit) != 0)
        {
            state->flags = (u8)(state->flags | 0x0c);
            *(u8*)((char*)refs + 8) = 23;
        }
        else
        {
            *(u8*)((char*)refs + 8) = 22;
        }
    }
}

void magiccavetop_free(int* obj)
{
    MagiccavetopState* state = ((GameObject*)obj)->extra;
    MagiccavetopPlacement* def = *(MagiccavetopPlacement**)&((GameObject*)obj)->anim.placementData;
    void* p;
    void* r;
    stopRumble2();
    p = Obj_GetPlayerObject();
    if (p != NULL)
    {
        r = (void*)Player_GetStaffObject((int)p);
        if (r != NULL)
        {
            staffSetGlow(r, 5, 0);
        }
    }
    if (state->subState == MAGICCAVETOP_SUBSTATE_LOADED)
    {
        if (def->noLoad == 0)
        {
            mapUnload(mapGetDirIdx(def->mapId), 0x20000000);
        }
    }
}

typedef struct MagicCaveTopFxArgs
{
    u8 pad[12];
    f32 x;
    f32 y;
    f32 z;
} MagicCaveTopFxArgs;

void magiccavetop_update(int* obj)
{

    MagicCaveTopFxArgs fx;
    int* player;
    MagiccavetopState* sub;
    MagiccavetopPlacement* def;
    int gb;
    u8 dirIdx;
    int range;
    void* staff;
    f32 dist;
    f32 t;

    player = Obj_GetPlayerObject();
    sub = ((GameObject*)obj)->extra;
    def = *(MagiccavetopPlacement**)&((GameObject*)obj)->anim.placementData;
    gb = 0;
    if (player != NULL)
    {
        if (GameBit_Get(MAGICCAVE_GAMEBIT_WARP_READY) != 0)
        {
            GameBit_Set(MAGICCAVE_GAMEBIT_WARP_READY, 0);
            (*gMapEventInterface)->setObjGroupStatus(def->mapId, def->objGroup, 0);
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            unlockLevel(0, 0, 1);
            sub->subState = MAGICCAVETOP_SUBSTATE_WARP_DONE;
            return;
        }
        dirIdx = mapGetDirIdx(def->mapId);
        dist = vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
        gb = GameBit_Get(def->visibleGameBit);
        switch (sub->subState)
        {
        case MAGICCAVETOP_SUBSTATE_IDLE:
            range = def->rangeInner * 2;
            if (dist < (f32)(range * range))
            {
                if (def->noLoad == 0)
                {
                    loadMapAndParent(def->mapId);
                }
                sub->subState = MAGICCAVETOP_SUBSTATE_LOADED;
            }
            break;
        case MAGICCAVETOP_SUBSTATE_LOADED:
            range = def->rangeOuter * 2;
            if (dist > (f32)(range * range))
            {
                if (def->noLoad == 0)
                {
                    mapUnload(dirIdx, 0x20000000);
                }
                sub->subState = MAGICCAVETOP_SUBSTATE_IDLE;
            }
            else if (dist < gMagicCaveTopWarpDistSq && gb != 0)
            {
                sub->subState = MAGICCAVETOP_SUBSTATE_WARPING;
                (*gMapEventInterface)->setObjGroupStatus(def->mapId, def->objGroup, 1);
                (*gMapEventInterface)->setMapAct(def->mapId, def->mapAct);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            }
            break;
        case MAGICCAVETOP_SUBSTATE_WARPING:
            GameBit_Set(MAGICCAVE_GAMEBIT_WARP_DEST, def->gameBitValue);
            if (def->noLoad != 0)
            {
                unlockLevel(0, 0, 1);
                lockLevel(def->lockDirId, 0);
                lockLevel(def->lockDirId, 1);
            }
            else
            {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(((GameObject*)obj)->anim.mapEventSlot), 0);
                lockLevel(dirIdx, 1);
            }
            if (((GameObject*)obj)->anim.mapEventSlot == 0xd)
            {
                GameBit_Set(MAGICCAVETOP_GAMEBIT_SLOT_D_CLEAR, 0);
            }
            warpToMap(def->warpMapId, 0);
            break;
        case MAGICCAVETOP_SUBSTATE_WARP_DONE:
            if (dist > gMagicCaveTopWarpDistSq)
            {
                sub->subState = MAGICCAVETOP_SUBSTATE_LOADED;
            }
            break;
        }
        if ((sub->flags & 4) == 0)
        {
            if (dist >= gMagicCaveTopRumbleStartDistSq)
            {
                sub->timer = lbl_803E3C38;
                sub->flags &= ~2;
            }
            else if ((sub->flags & 2) == 0)
            {
                if ((sub->flags & 1) != 0)
                {
                    if (dist < gMagicCaveTopRumbleStopDistSq)
                    {
                        stopRumble();
                        if (player != NULL)
                        {
                            staff = (void*)Player_GetStaffObject((int)player);
                            if (staff != NULL)
                            {
                                staffSetGlow(staff, 5, 0);
                            }
                        }
                        sub->rumbleState = 0;
                    }
                    else if (dist < gMagicCaveTopRumblePulseDistSq)
                    {
                        if (sub->rumbleState == 1)
                        {
                            stopRumble();
                            if (player != NULL)
                            {
                                staff = (void*)Player_GetStaffObject((int)player);
                                if (staff != NULL)
                                {
                                    staffSetGlow(staff, 5, 0);
                                }
                            }
                            sub->rumbleState = 0;
                        }
                        else
                        {
                            stopRumble2();
                            if (player != NULL)
                            {
                                staff = (void*)Player_GetStaffObject((int)player);
                                if (staff != NULL)
                                {
                                    staffSetGlow(staff, 5, 0);
                                }
                            }
                            sub->rumbleState = 1;
                        }
                    }
                    else
                    {
                        stopRumble2();
                        if (player != NULL)
                        {
                            staff = (void*)Player_GetStaffObject((int)player);
                            if (staff != NULL)
                            {
                                staffSetGlow(staff, 5, 0);
                            }
                        }
                        sub->rumbleState = 1;
                    }
                    sub->flags &= ~1;
                    sub->timer += timeDelta;
                }
                else if (dist < gMagicCaveTopRumbleStartDistSq)
                {
                    doRumble(gMagicCaveTopRumbleStrength);
                    if (player != NULL)
                    {
                        staff = (void*)Player_GetStaffObject((int)player);
                        if (staff != NULL)
                        {
                            staffSetGlow(staff, 5, 2);
                        }
                    }
                    sub->flags |= 1;
                    sub->timer += timeDelta;
                }
                if (sub->timer > gMagicCaveTopRumbleDuration)
                {
                    sub->flags |= 2;
                }
            }
        }
    }
    if (gb != 0)
    {
        if (lbl_803E3C38 == sub->fadeTimer)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_door_creak);
        }
        sub->fadeTimer += timeDelta;
        if (sub->fadeTimer > gMagicCaveTopFadeMax)
        {
            sub->fadeTimer = gMagicCaveTopFadeMax;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(gMagicCaveTopAlphaMax * (sub->fadeTimer / gMagicCaveTopFadeMax));
        }
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        t = lbl_803E3C38;
        fx.x = t;
        fx.y = gMagicCaveTopBurstHeight1;
        fx.z = t;
        if ((sub->flags & 8) != 0)
        {
            objfx_spawnArcedBurst(obj, 1, gMagicCaveTopBurstRadius, 5, 2, 0x32, gMagicCaveTopBurstSpreadX, gMagicCaveTopBurstSpreadY, gMagicCaveTopBurstSpreadZ, fx.pad,
                                  0);
            fx.y = gMagicCaveTopBurstHeight2;
            objfx_spawnArcedBurst(obj, 5, gMagicCaveTopBurstRadius, 5, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
        else
        {
            objfx_spawnArcedBurst(obj, 1, gMagicCaveTopBurstRadius, 2, 2, 0x32, gMagicCaveTopBurstSpreadX, gMagicCaveTopBurstSpreadY, gMagicCaveTopBurstSpreadZ, fx.pad,
                                  0);
            fx.y = gMagicCaveTopBurstHeight2;
            objfx_spawnArcedBurst(obj, 5, gMagicCaveTopBurstRadius, 2, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
    }
}
