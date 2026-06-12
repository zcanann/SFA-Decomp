#include "main/effect_interfaces.h"
#include "main/dll/savegame.h"

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);


/*
 * --INFO--
 *
 * Function: dll_91_func03
 * EN v1.0 Address: 0x800FA5D8
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FA874
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void dll_91_func01_nop(void);

void dll_91_func00_nop(void);

void dll_92_func01_nop(void)
{
}

void dll_92_func00_nop(void)
{
}

void dll_93_func01_nop(void);

void dll_93_func00_nop(void);

void dll_94_func01_nop(void);

void dll_94_func00_nop(void);

void dll_95_func01_nop(void);

void dll_95_func00_nop(void);

void dll_96_func01_nop(void);

void dll_96_func00_nop(void);

void dll_97_func01_nop(void);

void dll_97_func00_nop(void);

void dll_98_func01_nop(void);

void dll_98_func00_nop(void);

void dll_99_func01_nop(void);

void dll_99_func00_nop(void);

/* Stubs to align function set with v1.0 asm. The dll_xx_func03 stubs follow
 * the same large-struct + vtable-call pattern as foodbag's func03s; matching
 * bodies needs proper struct recovery as follow-up. */
extern u8 lbl_803171C0[];
extern u8 lbl_803DB930[8];
extern u8 lbl_803DB938[8];
extern u8 lbl_803DB948[8];
extern u8 lbl_803DB950[8];
extern f32 lbl_803E1270;
extern f32 lbl_803E1278;
extern f32 lbl_803E12F0;
extern f32 lbl_803E12F8;
extern f32 lbl_803E1340;
extern f32 lbl_803E1344;
extern f32 lbl_803E1348;
extern f32 lbl_803E1350;
extern f32 lbl_803E1358;
extern f32 lbl_803E1368;
extern f32 lbl_803E1210;
extern f32 lbl_803E1214;
extern f32 lbl_803E1218;
extern f32 lbl_803E121C;
extern f32 lbl_803E1220;
extern f32 lbl_803E1224;
extern f32 lbl_803E1228;
extern f32 lbl_803E122C;
extern f32 lbl_803E1230;
extern f32 lbl_803E1234;
extern f32 lbl_803E1238;

typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 v44; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 v58, v59, v5a, v5b, v5c; /* +0x58..+0x5c */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

extern u8 lbl_80316FF8[];
extern u8 lbl_80317528[];
extern u8 lbl_803DB928[8];
extern u8 lbl_803DB940[8];
extern f32 lbl_803E11D8;
extern f32 lbl_803E11DC;
extern f32 lbl_803E11E0;
extern f32 lbl_803E11E4;
extern f32 lbl_803E11E8;
extern f32 lbl_803E11EC;
extern f32 lbl_803E11F0;
extern f32 lbl_803E11F4;
extern f32 lbl_803E11F8;
extern f32 lbl_803E11FC;
extern f32 lbl_803E1200;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;
extern f32 lbl_803E1298;
extern f32 lbl_803E129C;
extern f32 lbl_803E12A0;
extern f32 lbl_803E12A4;
extern f32 lbl_803E12A8;
extern f32 lbl_803E12AC;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;
extern f32 lbl_803E12C0;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12C8;
extern f32 lbl_803E12CC;
extern f32 lbl_803E12D0;
extern f32 lbl_803E12D4;
extern f32 lbl_803E12D8;
extern f32 lbl_803E1318;
extern f32 lbl_803E131C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E1328;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1338;
extern f32 lbl_803E133C;

void dll_91_func03(int sourceObj, int variant, int posSource, uint flags);


void dll_92_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs
)
{
    GfxBuf buf;
    GfxCmd* e;
    u8* base = lbl_803171C0;
    f32 s = lbl_803E1210;
    if (extraArgs != (f32*)0)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = lbl_803E1214;
    e[0].y = lbl_803E1214;
    e[0].z = lbl_803E1214;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB930;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = lbl_803E1218;
    }
    else
    {
        e[1].x = lbl_803E121C;
    }
    e[1].y = lbl_803E1214;
    e[1].z = lbl_803E1214;
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = lbl_803E1220 * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = lbl_803E1224 * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1228;
    e[3].y = lbl_803E1210;
    e[3].z = lbl_803E1214;
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = lbl_803E122C;
    e[4].y = lbl_803E122C;
    e[4].z = lbl_803E1230;
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1228;
    e[5].y = lbl_803E1210;
    e[5].z = lbl_803E1214;
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = lbl_803E1234;
    e[6].y = lbl_803E1234;
    e[6].z = lbl_803E1210;
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1228;
    e[7].y = lbl_803E1210;
    e[7].z = lbl_803E1214;
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB930;
    e[8].mode = 4;
    e[8].x = lbl_803E1214;
    e[8].y = lbl_803E1214;
    e[8].z = lbl_803E1214;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E1214;
    buf.pos[1] = lbl_803E1214;
    buf.pos[2] = lbl_803E1214;
    buf.col[0] = lbl_803E1214;
    buf.col[1] = lbl_803E1214;
    buf.col[2] = lbl_803E1214;
    buf.scale = lbl_803E1238;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 6;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e;
    buf.hw[0] = *(s16*)(base + 0x6c);
    buf.hw[1] = *(s16*)(base + 0x6e);
    buf.hw[2] = *(s16*)(base + 0x70);
    buf.hw[3] = *(s16*)(base + 0x72);
    buf.hw[4] = *(s16*)(base + 0x74);
    buf.hw[5] = *(s16*)(base + 0x76);
    buf.hw[6] = *(s16*)(base + 0x78);
    buf.cmds = buf.entries;
    buf.flags = 0x4000400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0 && (uint)posSource != 0)
        {
            buf.pos[0] = lbl_803E1214 + (*(f32*)(sourceObj + 0x18) + *(f32*)(posSource + 0xc));
            buf.pos[1] = lbl_803E1214 + (*(f32*)(sourceObj + 0x1c) + *(f32*)(posSource + 0x10));
            buf.pos[2] = lbl_803E1214 + (*(f32*)(sourceObj + 0x20) + *(f32*)(posSource + 0x14));
        }
        else if ((uint)sourceObj != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((uint)posSource != 0)
        {
            buf.pos[0] += *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(posSource + 0x10);
            buf.pos[2] += *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, 0x3c, 0);
}

extern u8 lbl_80317260[];
extern f32 lbl_803E1240;
extern f32 lbl_803E1244;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1254;
extern f32 lbl_803E1258;


void dll_93_func03(int sourceObj, int variant, int posSource, uint flags);

extern u8 lbl_80317488[];
extern u8 lbl_80317810[];
extern u8 lbl_803178B0[];
extern u8 lbl_80317AF8[];
extern f32 lbl_803E1268;
extern f32 lbl_803E126C;
extern f32 lbl_803E1274;
extern f32 lbl_803E127C;
extern f32 lbl_803E1280;
extern f32 lbl_803E1284;
extern f32 lbl_803E1288;
extern f32 lbl_803E128C;
extern f32 lbl_803E1290;
extern f32 lbl_803E12E8;
extern f32 lbl_803E12EC;
extern f32 lbl_803E12F4;
extern f32 lbl_803E12FC;
extern f32 lbl_803E1300;
extern f32 lbl_803E1304;
extern f32 lbl_803E1308;
extern f32 lbl_803E130C;
extern f32 lbl_803E1310;
extern f32 lbl_803E134C;
extern f32 lbl_803E1354;
extern f32 lbl_803E135C;
extern f32 lbl_803E1360;
extern f32 lbl_803E1364;

void dll_94_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs );

extern u8 lbl_803175E8[];

void dll_95_func03(int sourceObj, int variant, int posSource);

int dll_96_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_97_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs );

void dll_98_func03(int sourceObj, int variant, int posSource, uint flags, int arg5, int extraArgs);

void dll_99_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs );
