/*
 * playershadow (DLL 0x000D) - the player's projected ground shadow / footfall fx.
 *
 * The TU proper is small: a gPlayerShadowMode setter (playerShadow_setMode,
 * which only accepts 0 or values >= 0xa) and playerShadow_renderObject, which
 * builds an 8-corner swept-sphere box (radius/height chosen per shadow mode,
 * modes 0xb..0x11) around the object, runs it through the terrain hit-detect
 * pipeline, then hands the resulting tri hits to fn_800A3AF0. fn_800A3AF0
 * walks those hits and, for surface types 0x10-0x17, scatters bone/foot
 * particle effects (partfx ids 0x72/0x73/0x190) at random barycentric points
 * on the struck triangles relative to the camera.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/bonespawndata_struct.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/camera.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/track_dolphin_api.h"

s16 gPlayerShadowCamRotY;
s16 lbl_803DD29A;
u8 gPlayerShadowMode;

/* foot/bone particle ids scattered per struck-triangle surface type
   (index-style; roles opaque). A on surfaces 0x10/0x12; B on 0x11/0x14/0x15;
   C spawned 3x on surface 0x17. */
#define PLAYERSHADOW_PARTFX_A 0x72
#define PLAYERSHADOW_PARTFX_B 0x73
#define PLAYERSHADOW_PARTFX_C 0x190

extern u8 gPlayerShadowMode;
__declspec(section ".rodata") u32 gPlayerShadowDefaultParams[4] = {0, 0, 0, 0};
extern s16 lbl_803DD29A;
extern s16 gPlayerShadowCamRotY;
extern void fn_80069968(int* outA, int* outB);
extern void fn_80069958(int** out);

f32 gPlayerShadowCamDelta[3] = {0.0f, 0.0f, 0.0f};

#pragma peephole off
#pragma scheduling off
/* Walks the tri-hit table under the player and, for ground surface types
 * 0x10-0x17, spawns footfall particle effects at a random barycentric point
 * on each struck triangle. offsX/offsZ = obj position minus the tile origin,
 * so (vert - offs) + objPos recovers the world-space triangle corners. */
union PlayerShadowConstF32 { f32 f; };
#pragma explicit_zero_data on
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF468 = { 0.1f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF46C = { 0.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF470 = { 1.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF474 = { 1000.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF478 = { 0.35f };
#pragma explicit_zero_data off
extern const union PlayerShadowConstF32 lbl_803DF488;
extern const union PlayerShadowConstF32 lbl_803DF48C;
extern const union PlayerShadowConstF32 lbl_803DF490;
extern const union PlayerShadowConstF32 lbl_803DF494;
extern const union PlayerShadowConstF32 lbl_803DF498;
extern const union PlayerShadowConstF32 lbl_803DF49C;
extern const union PlayerShadowConstF32 lbl_803DF4A0;
extern const union PlayerShadowConstF32 lbl_803DF4A4;

void fn_800A3AF0(PlayerShadowTriHit* hits, int count, f32 offsX, f32 offsZ, GameObject* obj)
{
    BoneSpawnData data;
    CameraViewSlot* cam;
    u8 found;
    u8 surfType;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 len;
    f32 sc;
    f32 p0x;
    f32 p0y;
    f32 p0z;
    f32 p1x;
    f32 p1y;
    f32 p1z;
    f32 p2x;
    f32 p2y;
    f32 p2z;
    f32 r1;
    f32 r2;
    f32 sqrtR2;
    f32 w0;
    f32 w1;
    f32 w2;

    found = 0;
    cam = Camera_GetCurrentViewSlot();
    {
        s16 camRotY = cam->pitch;
        lbl_803DD29A = cam->yaw;
        gPlayerShadowCamRotY = camRotY;
    }
    dx = cam->x - obj->anim.localPosX;
    dy = cam->y - obj->anim.localPosY;
    dz = cam->z - obj->anim.localPosZ;
    for (i = 0; i < count; i++)
    {
        surfType = hits[i].surfaceType;
        if ((s8)surfType == 0x12 || (u8)(surfType - 0x10) <= 1 || (u8)(surfType - 0x14) <= 1 || (s8)surfType == 0x17)
        {
            gPlayerShadowCamDelta[0] = dx;
            gPlayerShadowCamDelta[1] = dy;
            gPlayerShadowCamDelta[2] = dz;
            {
                f32 dydy = dy * dy;
                len = sqrtf(dydy + dx * dx + dz * dz);
            }
            sc = lbl_803DF468.f * len;
            if (lbl_803DF46C.f != len)
            {
                dx = dx / len;
                dy = dy / len;
                dz = dz / len;
            }
            dx = dx * sc;
            dy = dy * sc;
            dz = dz * sc;
            data.x = *(f32*)&lbl_803DF46C.f;
            data.y = *(f32*)&lbl_803DF46C.f;
            data.z = *(f32*)&lbl_803DF46C.f;
            data.scale = lbl_803DF470.f;
            data.unk4 = 0;
            data.unk2 = 0;
            data.unk0 = 0;
            found = 1;
            i = count;
        }
    }
    if (found)
    {
        int j;
        for (j = 0; j < count; j++)
        {
            PlayerShadowTriHit* hit = &hits[j];
            u8 surfType = hit->surfaceType;
            if ((s8)surfType == 0x12 || (u8)(surfType - 0x10) <= 1 || (u8)(surfType - 0x14) <= 1 ||
                (s8)surfType == 0x17)
            {
                int rt;
                p0x = obj->anim.localPosX + ((f32)hit->vertX[0] - offsX);
                p0y = (f32)hit->vertY[0];
                p0z = obj->anim.localPosZ + ((f32)hit->vertZ[0] - offsZ);
                p1x = obj->anim.localPosX + ((f32)hit->vertX[1] - offsX);
                p1y = (f32)hit->vertY[1];
                p1z = obj->anim.localPosZ + ((f32)hit->vertZ[1] - offsZ);
                p2x = obj->anim.localPosX + ((f32)hit->vertX[2] - offsX);
                p2y = (f32)hit->vertY[2];
                p2z = obj->anim.localPosZ + ((f32)hit->vertZ[2] - offsZ);
                r1 = randomGetRange(1, 1000) / lbl_803DF474.f;
                r2 = randomGetRange(1, 1000) / lbl_803DF474.f;
                sqrtR2 = sqrtf(r2);
                w0 = lbl_803DF470.f - sqrtR2;
                {
                    f32 omr = lbl_803DF470.f - r1;
                    w1 = omr * sqrtR2;
                }
                w2 = r1 * sqrtR2;
                data.x = w0 * p0x + w1 * p1x + w2 * p2x;
                data.y = w0 * p0y + w1 * p1y + w2 * p2y;
                data.z = w0 * p0z + w1 * p1z + w2 * p2z;
                data.y = data.y + lbl_803DF478.f;
                rt = (s8)hit->surfaceType;
                if (rt == 0x12 || rt == 0x10)
                {
                    if (randomGetRange(0, 0x1e) == 1)
                    {
                        (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_A, &data, 0x200001, -1, NULL);
                    }
                }
                else if (rt == 0x11)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_B, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x14)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_B, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x15)
                {
                    if (randomGetRange(0, 8) == 2)
                    {
                        (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_B, &data, 0x111, -1, NULL);
                    }
                }
                else if (rt == 0x17)
                {
                    (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_C, &data, 0x111, -1, NULL);
                    (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_C, &data, 0x111, -1, NULL);
                    (*gPartfxInterface)->spawnObject(obj, PLAYERSHADOW_PARTFX_C, &data, 0x111, -1, NULL);
                }
            }
        }
    }
}

__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF488 = { 10.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF48C = { 400.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF490 = { 130.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF494 = { 20.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF498 = { 100.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF49C = { 75.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF4A0 = { 230.0f };
__declspec(section ".sdata2") const union PlayerShadowConstF32 lbl_803DF4A4 = { 125.0f };


#pragma scheduling reset
void playerShadow_setMode(u8 v)
{
    if (v == 0 || v >= 0xa)
    {
        gPlayerShadowMode = v;
    }
}

void* playerShadow_funcs[10] = {(void*)0x00000000,
                                (void*)0x00000000,
                                (void*)0x00000000,
                                (void*)0x00050000,
                                playerShadow_initialise,
                                playerShadow_release,
                                (void*)0x00000000,
                                playerShadow_func03_nop,
                                playerShadow_renderObject,
                                playerShadow_setMode};

#pragma scheduling off
void playerShadow_renderObject(GameObject* obj)
{
    u32* defaults;
    u32 params[4];
    int* tileInfo;
    int hitTable;
    int hitCount;
    int hitTableValue;
    u32 mode;
    TrackQueryBounds hitData;
    f32 verts[8][3];
    f32 height;
    f32 radius;

    defaults = gPlayerShadowDefaultParams;
    *(struct PlayerShadowParamsBlob*)params = *(struct PlayerShadowParamsBlob*)defaults;
    hitTable = 0;

    if (gPlayerShadowMode == 0)
    {
        return;
    }

    mode = gPlayerShadowMode - 0xb;
    switch (mode)
    {
    case 0:
        radius = lbl_803DF488.f;
        height = radius;
        break;
    case 1:
        radius = lbl_803DF48C.f;
        height = lbl_803DF490.f;
        break;
    case 2:
        radius = lbl_803DF494.f;
        height = lbl_803DF488.f;
        break;
    case 3:
        radius = lbl_803DF494.f;
        height = lbl_803DF488.f;
        break;
    case 4:
        radius = lbl_803DF498.f;
        height = lbl_803DF490.f;
        break;
    case 5:
        radius = lbl_803DF49C.f;
        height = lbl_803DF4A0.f;
        break;
    case 6:
        radius = lbl_803DF4A4.f;
        height = radius;
        break;
    default:
        radius = lbl_803DF46C.f;
        height = radius;
        break;
    }

    verts[0][0] = (obj)->anim.localPosX - radius;
    verts[0][1] = (obj)->anim.localPosY + height;
    verts[0][2] = (obj)->anim.localPosZ - radius;
    verts[1][0] = (obj)->anim.localPosX - radius;
    verts[1][1] = (obj)->anim.localPosY + height;
    verts[1][2] = (obj)->anim.localPosZ + radius;
    verts[2][0] = (obj)->anim.localPosX + radius;
    verts[2][1] = (obj)->anim.localPosY + height;
    verts[2][2] = (obj)->anim.localPosZ + radius;
    verts[3][0] = (obj)->anim.localPosX + radius;
    verts[3][1] = (obj)->anim.localPosY + height;
    verts[3][2] = (obj)->anim.localPosZ - radius;
    verts[4][0] = (obj)->anim.localPosX - radius;
    verts[4][1] = (obj)->anim.localPosY - height;
    verts[4][2] = (obj)->anim.localPosZ - radius;
    verts[5][0] = (obj)->anim.localPosX - radius;
    verts[5][1] = (obj)->anim.localPosY - height;
    verts[5][2] = (obj)->anim.localPosZ + radius;
    verts[6][0] = (obj)->anim.localPosX + radius;
    verts[6][1] = (obj)->anim.localPosY - height;
    verts[6][2] = (obj)->anim.localPosZ + radius;
    verts[7][0] = (obj)->anim.localPosX + radius;
    verts[7][1] = (obj)->anim.localPosY - height;
    verts[7][2] = (obj)->anim.localPosZ - radius;

    hitDetect_calcSweptSphereBounds(&hitData, &verts[0][0], &verts[4][0], (f32*)params, 4);
    hitDetectFn_800691c0(obj, &hitData, 0x84, 0);
    fn_80069968(&hitCount, &hitTable);
    hitTableValue = hitTable;
    fn_80069958(&tileInfo);
    fn_800A3AF0((PlayerShadowTriHit*)hitTableValue, hitCount, (obj)->anim.localPosX - tileInfo[0],
                (obj)->anim.localPosZ - tileInfo[2], obj);
}

#pragma peephole reset
#pragma scheduling reset
void playerShadow_func03_nop(void)
{
}

void playerShadow_release(void)
{
}

void playerShadow_initialise(void)
{
}
