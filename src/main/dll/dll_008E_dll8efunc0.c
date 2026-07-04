/*
 * dll8efunc0 (DLL 0x8E) - one of the foodbag modgfx effect spawners
 * (dll_NN_func03 family, see foodbag.h). func03 builds a multi-command
 * FbBuf and hands it to the modgfx interface to spawn a randomized
 * particle burst (a flame/spark fan: textured layer-0/1/2 commands plus
 * mode-0x80 emitter markers, the lone &gDll8EEffectTexture texture). variant 0
 * vs 1 selects two different random spawn-box ranges for the lead
 * command; flag bit 0 offsets the burst position from sourceObj
 * (offsets 0x18/0x1c/0x20) and/or posSource (offsets 0xc/0x10/0x14).
 * func00/func01 are unused stub slots; effect params come from the
 * resource tables gDll8EEffectHwParams (the halfword parameter block copied
 * into buf.hw[]) and gDll8EEffectVtxColorTable (the vertex/color table passed to
 * spawnEffect). gDll8EEffectSpawnResource is the lone extra resource handed to
 * spawnEffect alongside the &gDll8EEffectTexture texture.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 gDll8EEffectHwParams[];
extern u8 gDll8EEffectVtxColorTable[];
extern u8 gDll8EEffectTexture;
extern u8 gDll8EEffectSpawnResource[8];
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E114C;
extern f32 lbl_803E1150;
extern f32 lbl_803E1154;
extern f32 lbl_803E1158;
extern f32 lbl_803E115C;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E116C;

#pragma opt_propagation off
void dll_8E_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    FbCmd* p;
    FbCmd* e = buf.entries;
    u8* base;
    f32 rz;
    f32 ry;

    p = e;
    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDll8EEffectTexture;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDll8EEffectTexture;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
        p++;
    }
    rz = (f32)(int)
    randomGetRange(0, 0xfffe);
    ry = (f32)(int)
    randomGetRange(-0xbb8, -0x2ee0);
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = NULL;
    p[0].mode = 0x80;
    p[0].x = lbl_803E1138;
    p[0].y = ry;
    p[0].z = rz;
    p[1].layer = 0;
    p[1].flags = 3;
    p[1].tex = &gDll8EEffectTexture;
    p[1].mode = 4;
    p[1].x = lbl_803E1138;
    p[1].y = lbl_803E1138;
    p[1].z = lbl_803E1138;
    p[2].layer = 0;
    p[2].flags = 3;
    p[2].tex = &gDll8EEffectTexture;
    p[2].mode = 2;
    p[2].x = lbl_803E113C;
    p[2].y = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x32) + lbl_803E1140;
    p[2].z = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x14) + lbl_803E1148;
    p[3].layer = 1;
    p[3].flags = 3;
    p[3].tex = &gDll8EEffectTexture;
    p[3].mode = 4;
    if ((int)randomGetRange(0, 0xa) == 0)
    {
        p[3].x = lbl_803E114C + (f32)(int)
        randomGetRange(0, 0x1e);
    }
    else
    {
        p[3].x = lbl_803E1150 + (f32)(int)
        randomGetRange(0, 0xa);
    }
    p[3].y = lbl_803E1138;
    p[3].z = lbl_803E1138;
    p[4].layer = 2;
    p[4].flags = 0;
    p[4].tex = NULL;
    p[4].mode = 0x80;
    p[4].x = lbl_803E1138;
    p[4].y = lbl_803E1138;
    p[4].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[5].layer = 1;
    p[5].flags = 3;
    p[5].tex = &gDll8EEffectTexture;
    p[5].mode = 2;
    p[5].x = lbl_803E1154;
    p[5].y = lbl_803E1158;
    p[5].z = lbl_803E115C;
    p[6].layer = 2;
    p[6].flags = 0;
    p[6].tex = NULL;
    p[6].mode = 0x80;
    p[6].x = lbl_803E1138;
    p[6].y = lbl_803E1138;
    p[6].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[7].layer = 2;
    p[7].flags = 3;
    p[7].tex = &gDll8EEffectTexture;
    p[7].mode = 4;
    p[7].x = lbl_803E1138;
    p[7].y = lbl_803E1138;
    p[7].z = lbl_803E1138;
    p[8].layer = 2;
    p[8].flags = 3;
    p[8].tex = &gDll8EEffectTexture;
    p[8].mode = 2;
    p[8].x = lbl_803E1160;
    p[8].y = lbl_803E1164;
    p[8].z = lbl_803E1168;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = *(f32*)&lbl_803E1138;
    if (variant == 0)
    {
        buf.pos[1] = lbl_803E1138;
    }
    else if (variant == 1)
    {
        buf.pos[1] = lbl_803E116C;
    }
    buf.pos[2] = *(f32*)&lbl_803E1138;
    buf.col[0] = lbl_803E1138;
    buf.col[1] = lbl_803E1138;
    buf.col[2] = *(f32*)&lbl_803E1138;
    buf.scale = lbl_803E1164;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 3;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (FbCmd*)((u8*)p + 0xd8) - e;
    base = gDll8EEffectHwParams;
    buf.hw[0] = *(s16*)(base + 0);
    buf.hw[1] = *(s16*)(base + 2);
    buf.hw[2] = *(s16*)(base + 4);
    buf.hw[3] = *(s16*)(base + 6);
    buf.hw[4] = *(s16*)(base + 8);
    buf.hw[5] = *(s16*)(base + 0xa);
    buf.hw[6] = *(s16*)(base + 0xc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0 && (u32)posSource != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18) + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1138 + (*(f32*)(buf.ctx + 0x20) + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 3, gDll8EEffectVtxColorTable, 1, &gDll8EEffectSpawnResource, 0x26a, 0);
}
#pragma opt_propagation reset

void dll_8E_func01_nop(void)
{
}

void dll_8E_func00_nop(void)
{
}

u8 gDll8EEffectVtxColorTable[32] = { 0, 0, 0, 230, 5, 20, 0, 0, 0, 31, 0, 0, 255, 26, 5, 20, 0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15, 0, 16, 0, 0 };
u8 gDll8EEffectHwParams[16] = { 0, 0, 0, 140, 0, 140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/* descriptor/ptr table auto 0x80316c70-0x80316e30 */
u32 lbl_80316C70[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)dll_8E_func00_nop, (u32)dll_8E_func01_nop, 0x00000000, (u32)dll_8E_func03 };
u32 lbl_80316C90[95] = { 0x03e80000, 0x00000000, 0x000002c3, 0x0000fd3d, 0x000f0000, 0x00000000, 0xfc18001f, 0x0000fd3d, 0x0000fd3d, 0x002f0000, 0xfc180000, 0x0000003f, 0x0000fd3d, 0x000002c3, 0x004f0000, 0x00000000, 0x03e8005f, 0x000002c3, 0x000002c3, 0x006f0000, 0x03e80000, 0x0000007f, 0x000003e8, 0x07d00000, 0x0000001f, 0x02c307d0, 0xfd3d000f, 0x001f0000, 0x07d0fc18, 0x001f001f, 0xfd3d07d0, 0xfd3d002f, 0x001ffc18, 0x07d00000, 0x003f001f, 0xfd3d07d0, 0x02c3004f, 0x001f0000, 0x07d003e8, 0x005f001f, 0x02c307d0, 0x02c3006f, 0x001f03e8, 0x07d00000, 0x007f001f, 0x00000001, 0x000a0000, 0x000a0009, 0x00010002, 0x000b0001, 0x000b000a, 0x00020003, 0x000c0002, 0x000c000b, 0x00030004, 0x000d0003, 0x000d000c, 0x00040005, 0x000e0004, 0x000e000d, 0x00050006, 0x000f0005, 0x000f000e, 0x00060007, 0x00100006, 0x0010000f, 0x00070008, 0x00110007, 0x00110010, 0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080000, 0x00000001, 0x00020003, 0x00040005, 0x00060007, 0x00080009, 0x000a000b, 0x000c000d, 0x000e000f, 0x00100011, 0x0009000a, 0x000b000c, 0x000d000e, 0x000f0010, 0x00110000, 0x00000032, 0x00000064, 0x00000032, 0x00000000, 0x0032fa32, 0x00000000, 0x00000000 };
u32 lbl_80316E0C[9] = { 0x00000000, 0x00000000, 0x00000000, 0x00030000, (u32)dll_8F_func00_nop, (u32)dll_8F_func01_nop, 0x00000000, (u32)dll_8F_func03, 0x00000000 };

/* descriptor/ptr table auto 0x803e1178-0x803e1398 */
const f32 lbl_803E1178 = 0.0f;
const f32 lbl_803E117C = 0.2f;
const f32 lbl_803E1180 = 2.0f;
const f32 lbl_803E1184 = 300.0f;
const f32 lbl_803E1188 = 185.0f;
const f32 lbl_803E118C = 9.0f;
const f32 lbl_803E1190 = 0.3f;
const f32 lbl_803E1194 = 0.1f;
const f32 lbl_803E1198 = 7.0f;
const f32 lbl_803E119C = 1.0f;
const f32 lbl_803E11A0 = 0.0f;
const f32 lbl_803E11A4 = 255.0f;
const f32 lbl_803E11A8 = 1.0f;
const f32 lbl_803E11AC = 0.01f;
const f32 lbl_803E11B0 = 7.0f;
const f32 lbl_803E11B4 = 5.0f;
const f32 lbl_803E11B8 = 205.0f;
const f32 lbl_803E11BC = 150.0f;
const f32 lbl_803E11C0 = 10.0f;
const f32 lbl_803E11C4 = 155.0f;
const f32 lbl_803E11C8 = -10.0f;
const f32 lbl_803E11CC = 0.98f;
const f32 lbl_803E11D0 = 1.02f;
const f32 lbl_803E11D4 = 1.2f;
const f32 lbl_803E11D8 = 0.0f;
const f32 lbl_803E11DC = 255.0f;
const f32 lbl_803E11E0 = 3.0f;
const f32 lbl_803E11E4 = 0.03f;
const f32 lbl_803E11E8 = 1.75f;
const f32 lbl_803E11EC = 0.5f;
const f32 lbl_803E11F0 = 1.0f;
const f32 lbl_803E11F4 = 150.0f;
const f32 lbl_803E11F8 = 155.0f;
const f32 lbl_803E11FC = -10.0f;
const f32 lbl_803E1200 = 0.98f;
const f32 lbl_803E1204 = 1.02f;
const f32 lbl_803E1208 = 2.0f;
const f32 lbl_803E120C = 0.0f;
const f32 lbl_803E1210 = 1.0f;
const f32 lbl_803E1214 = 0.0f;
const f32 lbl_803E1218 = 155.0f;
const f32 lbl_803E121C = 55.0f;
const f32 lbl_803E1220 = 0.15f;
const f32 lbl_803E1224 = 0.1f;
const f32 lbl_803E1228 = -0.5f;
const f32 lbl_803E122C = 4.0f;
const f32 lbl_803E1230 = 25.0f;
const f32 lbl_803E1234 = 8.0f;
const f32 lbl_803E1238 = 2.0f;
const f32 lbl_803E123C = 0.0f;
const f32 lbl_803E1240 = 0.0f;
const f32 lbl_803E1244 = 1.0f;
const f32 lbl_803E1248 = 0.1f;
const f32 lbl_803E124C = 10.5f;
const f32 lbl_803E1250 = 255.0f;
const f32 lbl_803E1254 = 1.1f;
const f32 lbl_803E1258[2] = {1.2f, 0.0f};
const f64 lbl_803E1260 = 4503601774854144.0;
const f32 lbl_803E1268 = 1.0f;
const f32 lbl_803E126C = 0.0f;
const f32 lbl_803E1270 = 155.0f;
const f32 lbl_803E1274 = 55.0f;
const f32 lbl_803E1278 = 0.15f;
const f32 lbl_803E127C = 0.1f;
const f32 lbl_803E1280 = -0.5f;
const f32 lbl_803E1284 = 4.0f;
const f32 lbl_803E1288 = 25.0f;
const f32 lbl_803E128C = 8.0f;
const f32 lbl_803E1290 = 2.0f;
const f32 lbl_803E1294 = 0.0f;
const f32 lbl_803E1298 = 0.014f;
const f32 lbl_803E129C = 0.03f;
const f32 lbl_803E12A0 = 255.0f;
const f32 lbl_803E12A4 = 0.0f;
const f32 lbl_803E12A8 = 85.0f;
const f32 lbl_803E12AC = 80.0f;
const f32 lbl_803E12B0 = 100.0f;
const f32 lbl_803E12B4 = -80.0f;
const f32 lbl_803E12B8 = 2.0f;
const f32 lbl_803E12BC = 0.0f;
const f32 lbl_803E12C0 = 0.0f;
const f32 lbl_803E12C4 = 0.15f;
const f32 lbl_803E12C8 = 0.03f;
const f32 lbl_803E12CC = 10.5f;
const f32 lbl_803E12D0 = 4.0f;
const f32 lbl_803E12D4 = 1.0f;
const f32 lbl_803E12D8 = 255.0f;
const f32 lbl_803E12DC = 0.0f;
const f32 lbl_803E12E0 = 176.0f;
const f32 lbl_803E12E4 = -0.0f;
const f32 lbl_803E12E8 = 1.0f;
const f32 lbl_803E12EC = 0.0f;
const f32 lbl_803E12F0 = 155.0f;
const f32 lbl_803E12F4 = 55.0f;
const f32 lbl_803E12F8 = 0.15f;
const f32 lbl_803E12FC = 0.1f;
const f32 lbl_803E1300 = -0.5f;
const f32 lbl_803E1304 = 4.0f;
const f32 lbl_803E1308 = 25.0f;
const f32 lbl_803E130C = 8.0f;
const f32 lbl_803E1310[2] = {2.0f, 0.0f};
const f32 lbl_803E1318 = 0.0f;
const f32 lbl_803E131C = 0.22f;
const f32 lbl_803E1320 = 0.3f;
const f32 lbl_803E1324 = 255.0f;
const f32 lbl_803E1328 = -7.0f;
const f32 lbl_803E132C = 7.0f;
const f32 lbl_803E1330 = 1.0f;
const f32 lbl_803E1334 = -1.0f;
const f32 lbl_803E1338 = -2.0f;
const f32 lbl_803E133C = 2.0f;
const f32 lbl_803E1340 = 1.0f;
const f32 lbl_803E1344 = 0.0f;
const f32 lbl_803E1348 = 155.0f;
const f32 lbl_803E134C = 55.0f;
const f32 lbl_803E1350 = 0.15f;
const f32 lbl_803E1354 = 0.1f;
const f32 lbl_803E1358 = -0.5f;
const f32 lbl_803E135C = 4.0f;
const f32 lbl_803E1360 = 25.0f;
const f32 lbl_803E1364 = 8.0f;
const f32 lbl_803E1368[2] = {2.0f, 0.0f};
const f32 lbl_803E1370 = 0.0f;
const f32 lbl_803E1374 = 1.0f;
const f32 lbl_803E1378 = 0.2f;
const f32 lbl_803E137C = 0.01f;
const f32 lbl_803E1380 = 0.8f;
const f32 lbl_803E1384 = 255.0f;
const f32 lbl_803E1388 = 1.8f;
const f32 lbl_803E138C = 3.0f;
const f32 lbl_803E1390 = 4.0f;
const f32 lbl_803E1394 = 200.0f;
