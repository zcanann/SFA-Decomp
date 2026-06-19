/* DLL 0x011F (magiccavetop) — Magic Cave top area objects [0x8018AFC8-0x8018B7B0). */
#include "main/objseq.h"

extern u32 GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);

#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/player_objects.h"

typedef struct MagiccavetopPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x28 - 0x22];
} MagiccavetopPlacement;

typedef struct MagiccavetopObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} MagiccavetopObjectDef;

typedef struct MagiccavetopState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    u8 pad8[0xC - 0x8];
} MagiccavetopState;

extern f32 timeDelta;
extern int Obj_GetActiveModel(int* obj);
extern int* ObjModel_GetRenderOpTextureRefs(int model, int idx);
extern f32 lbl_803E3C4C;
extern void stopRumble2(void);
extern void staffSetGlow(void* a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void mapUnload(int idx, int flags);
extern void warpToMap(int mapId, int b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern int loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int idx, int b);
extern void stopRumble(void);
extern void doRumble(f32 v);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void objfx_spawnArcedBurst(int* obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 sx, f32 sy, f32 sz,
                                  void* args, int a);
extern f32 lbl_803E3C30;
extern f32 lbl_803E3C34;
extern f32 lbl_803E3C38;
extern f32 lbl_803E3C3C;
extern f32 lbl_803E3C40;
extern f32 lbl_803E3C44;
extern f32 lbl_803E3C48;
extern f32 lbl_803E3C50;
extern f32 lbl_803E3C54;
extern f32 lbl_803E3C58;
extern f32 lbl_803E3C5C;
extern f32 lbl_803E3C60;
extern f32 lbl_803E3C64;
extern f32 lbl_803E3C68;

int magiccavetop_getExtraSize(void) { return 0xc; }
int trickyguardspot_getExtraSize(void);

void magiccavetop_init(int* obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    int* refs;
    ((GameObject*)obj)->objectFlags = (u16)((u32)((GameObject*)obj)->objectFlags | 0x6000);
    if (GameBit_Get(((MagiccavetopObjectDef*)def)->unk1C) != 0)
    {
        ((MagiccavetopState*)state)->unk4 = lbl_803E3C4C;
    }
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(u8)def[0x23] << 8);
    refs = ObjModel_GetRenderOpTextureRefs(Obj_GetActiveModel(obj), 0);
    if (((MagiccavetopObjectDef*)def)->unk24 > 0)
    {
        if (GameBit_Get(((MagiccavetopObjectDef*)def)->unk24) != 0)
        {
            ((MagiccavetopState*)state)->unk1 = (u8)(((MagiccavetopState*)state)->unk1 | 0x0c);
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
    u8* state = ((GameObject*)obj)->extra;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
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
    if (state[0] == 1)
    {
        if (def[0x22] == 0)
        {
            mapUnload(mapGetDirIdx(def[0x1f]), 0x20000000);
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
    extern void GameBit_Set(int eventId, int value);
    MagicCaveTopFxArgs fx;
    int* player;
    u8* sub;
    u8* def;
    int gb;
    u8 dirIdx;
    int range;
    void* staff;
    f32 dist;
    f32 t;

    player = Obj_GetPlayerObject();
    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    gb = 0;
    if (player != NULL)
    {
        if (GameBit_Get(0x91e) != 0)
        {
            GameBit_Set(0x91e, 0);
            (*gMapEventInterface)->setObjGroupStatus(def[0x1f], def[0x1a], 0);
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            unlockLevel(0, 0, 1);
            *sub = 3;
            return;
        }
        dirIdx = mapGetDirIdx(def[0x1f]);
        dist = vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
        gb = GameBit_Get(((MagiccavetopPlacement*)def)->unk1C);
        switch (*sub)
        {
        case 0:
            range = def[0x19] * 2;
            if (dist < (f32)(range * range))
            {
                if (def[0x22] == 0)
                {
                    loadMapAndParent(def[0x1f]);
                }
                *sub = 1;
            }
            break;
        case 1:
            range = def[0x18] * 2;
            if (dist > (f32)(range * range))
            {
                if (def[0x22] == 0)
                {
                    mapUnload(dirIdx, 0x20000000);
                }
                *sub = 0;
            }
            else if (dist < lbl_803E3C30 && gb != 0)
            {
                *sub = 2;
                (*gMapEventInterface)->setObjGroupStatus(def[0x1f], def[0x1a], 1);
                (*gMapEventInterface)->setMapAct(def[0x1f], def[0x1b]);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            }
            break;
        case 2:
            GameBit_Set(0x1b8, ((MagiccavetopPlacement*)def)->unk21);
            if (def[0x22] != 0)
            {
                unlockLevel(0, 0, 1);
                lockLevel(def[0x1e], 0);
                lockLevel(def[0x1e], 1);
            }
            else
            {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(((GameObject*)obj)->anim.mapEventSlot), 0);
                lockLevel(dirIdx, 1);
            }
            if (((GameObject*)obj)->anim.mapEventSlot == 0xd)
            {
                GameBit_Set(0xe05, 0);
            }
            warpToMap(((MagiccavetopPlacement*)def)->unk20, 0);
            break;
        case 3:
            if (dist > lbl_803E3C30)
            {
                *sub = 1;
            }
            break;
        }
        if ((sub[1] & 4) == 0)
        {
            if (dist >= lbl_803E3C34)
            {
                *(f32*)(sub + 8) = lbl_803E3C38;
                sub[1] &= ~2;
            }
            else if ((sub[1] & 2) == 0)
            {
                if ((sub[1] & 1) != 0)
                {
                    if (dist < lbl_803E3C3C)
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
                        sub[2] = 0;
                    }
                    else if (dist < lbl_803E3C40)
                    {
                        if (sub[2] == 1)
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
                            sub[2] = 0;
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
                            sub[2] = 1;
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
                        sub[2] = 1;
                    }
                    sub[1] &= ~1;
                    *(f32*)(sub + 8) += timeDelta;
                }
                else if (dist < lbl_803E3C34)
                {
                    doRumble(lbl_803E3C44);
                    if (player != NULL)
                    {
                        staff = (void*)Player_GetStaffObject((int)player);
                        if (staff != NULL)
                        {
                            staffSetGlow(staff, 5, 2);
                        }
                    }
                    sub[1] |= 1;
                    *(f32*)(sub + 8) += timeDelta;
                }
                if (*(f32*)(sub + 8) > lbl_803E3C48)
                {
                    sub[1] |= 2;
                }
            }
        }
    }
    if (gb != 0)
    {
        if (lbl_803E3C38 == ((MagiccavetopState*)sub)->unk4)
        {
            Sfx_PlayFromObject(obj, 0x4a2);
        }
        ((MagiccavetopState*)sub)->unk4 += timeDelta;
        if (((MagiccavetopState*)sub)->unk4 > lbl_803E3C4C)
        {
            ((MagiccavetopState*)sub)->unk4 = lbl_803E3C4C;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(lbl_803E3C50 * (((MagiccavetopState*)sub)->unk4 / lbl_803E3C4C));
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
        fx.y = lbl_803E3C54;
        fx.z = t;
        if ((sub[1] & 8) != 0)
        {
            objfx_spawnArcedBurst(obj, 1, lbl_803E3C58, 5, 2, 0x32, lbl_803E3C5C, lbl_803E3C60, lbl_803E3C64, fx.pad,
                                  0);
            fx.y = lbl_803E3C68;
            objfx_spawnArcedBurst(obj, 5, lbl_803E3C58, 5, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
        else
        {
            objfx_spawnArcedBurst(obj, 1, lbl_803E3C58, 2, 2, 0x32, lbl_803E3C5C, lbl_803E3C60, lbl_803E3C64, fx.pad,
                                  0);
            fx.y = lbl_803E3C68;
            objfx_spawnArcedBurst(obj, 5, lbl_803E3C58, 2, 2, 0x14, 10.0f, 10.0f, 10.0f, fx.pad, 0);
        }
    }
}
