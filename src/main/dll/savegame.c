#include "ghidra_import.h"
#include "main/dll/savegame.h"

typedef struct {
  u32 mode;       /* +0x00 */
  f32 x, y, z;    /* +0x04 +0x08 +0x0c */
  void *tex;      /* +0x10 */
  u16 flags;      /* +0x14 */
  u8 layer;       /* +0x16 */
} GfxCmd;
extern undefined4* gModgfxInterface;

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
void dll_91_func01_nop(void) {}
void dll_91_func00_nop(void) {}
void dll_92_func01_nop(void) {}
void dll_92_func00_nop(void) {}
void dll_93_func01_nop(void) {}
void dll_93_func00_nop(void) {}
void dll_94_func01_nop(void) {}
void dll_94_func00_nop(void) {}
void dll_95_func01_nop(void) {}
void dll_95_func00_nop(void) {}
void dll_96_func01_nop(void) {}
void dll_96_func00_nop(void) {}
void dll_97_func01_nop(void) {}
void dll_97_func00_nop(void) {}
void dll_98_func01_nop(void) {}
void dll_98_func00_nop(void) {}
void dll_99_func01_nop(void) {}
void dll_99_func00_nop(void) {}

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

typedef struct {
  GfxCmd *cmds;   /* +0x00 */
  int ctx;        /* +0x04 */
  u8 pad0[0x18];  /* +0x08 */
  f32 col[3];     /* +0x20 */
  f32 pos[3];     /* +0x2c */
  f32 scale;      /* +0x38 */
  u32 v3c;        /* +0x3c */
  u32 v40;        /* +0x40 */
  s16 v44;        /* +0x44 */
  s16 hw[7];      /* +0x46 */
  u32 flags;      /* +0x54 */
  u8 v58, v59, v5a, v5b, v5c;  /* +0x58..+0x5c */
  s8 count;       /* +0x5d */
  u8 pad1[2];     /* +0x5e */
  GfxCmd entries[32];  /* +0x60 */
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

#pragma peephole off
#pragma scheduling off
void dll_91_func03(int param_1,int param_2,int param_3,uint param_4)
{
  GfxBuf buf;
  u8 *base = lbl_80316FF8;
  GfxCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 0x12; e[0].tex = base + 0x150; e[0].mode = 4;
  e[0].x = lbl_803E11D8; e[0].y = lbl_803E11D8; e[0].z = lbl_803E11D8;
  e[1].layer = 0; e[1].flags = 9; e[1].tex = base + 0x114; e[1].mode = 8;
  e[1].x = lbl_803E11D8; e[1].y = lbl_803E11D8; e[1].z = lbl_803E11DC;
  e[2].layer = 0; e[2].flags = 9; e[2].tex = base + 0x128; e[2].mode = 2;
  e[2].x = lbl_803E11E0; e[2].y = lbl_803E11E4; e[2].z = lbl_803E11E0;
  e[3].layer = 0; e[3].flags = 0x12; e[3].tex = base + 0x150; e[3].mode = 2;
  e[3].x = lbl_803E11E8; e[3].y = lbl_803E11EC; e[3].z = lbl_803E11E8;
  e[4].layer = 0; e[4].flags = 9; e[4].tex = base + 0x128; e[4].mode = 8;
  e[4].x = lbl_803E11DC; e[4].y = lbl_803E11D8; e[4].z = lbl_803E11DC;
  e[5].layer = 1; e[5].flags = 0x12; e[5].tex = base + 0x150; e[5].mode = 4;
  e[5].x = lbl_803E11DC; e[5].y = lbl_803E11D8; e[5].z = lbl_803E11D8;
  e[6].layer = 1; e[6].flags = 9; e[6].tex = base + 0x128; e[6].mode = 2;
  e[6].x = lbl_803E11F0; e[6].y = lbl_803E11F4; e[6].z = lbl_803E11F0;
  e[7].layer = 2; e[7].flags = 0; e[7].tex = (void *)0; e[7].mode = 0x20;
  e[7].x = lbl_803E11D8; e[7].y = lbl_803E11D8; e[7].z = lbl_803E11D8;
  e[8].layer = 3; e[8].flags = 9; e[8].tex = base + 0x114; e[8].mode = 8;
  e[8].x = lbl_803E11DC; e[8].y = lbl_803E11F8; e[8].z = lbl_803E11D8;
  e[9].layer = 3; e[9].flags = 0x12; e[9].tex = base + 0x150; e[9].mode = 0x100;
  e[9].x = lbl_803E11D8; e[9].y = lbl_803E11D8; e[9].z = lbl_803E11FC;
  e[10].layer = 3; e[10].flags = 5; e[10].tex = base + 0x188; e[10].mode = 2;
  e[10].x = lbl_803E1200; e[10].y = lbl_803E11F0; e[10].z = lbl_803E1200;
  e[11].layer = 3; e[11].flags = 4; e[11].tex = lbl_803DB928; e[11].mode = 2;
  e[11].x = lbl_803E1204; e[11].y = lbl_803E11F0; e[11].z = lbl_803E1204;
  e[12].layer = 4; e[12].flags = 9; e[12].tex = base + 0x114; e[12].mode = 8;
  e[12].x = lbl_803E11DC; e[12].y = lbl_803E11D8; e[12].z = lbl_803E11DC;
  e[13].layer = 4; e[13].flags = 0x12; e[13].tex = base + 0x150; e[13].mode = 0x100;
  e[13].x = lbl_803E11D8; e[13].y = lbl_803E11D8; e[13].z = lbl_803E11FC;
  e[14].layer = 4; e[14].flags = 5; e[14].tex = base + 0x188; e[14].mode = 2;
  e[14].x = lbl_803E1204; e[14].y = lbl_803E11F0; e[14].z = lbl_803E1204;
  e[15].layer = 4; e[15].flags = 4; e[15].tex = lbl_803DB928; e[15].mode = 2;
  e[15].x = lbl_803E1200; e[15].y = lbl_803E11F0; e[15].z = lbl_803E1200;
  e[16].layer = 5; e[16].flags = 2; e[16].tex = (void *)0; e[16].mode = 0x1000;
  e[16].x = lbl_803E11F0; e[16].y = lbl_803E11D8; e[16].z = lbl_803E11D8;
  e[17].layer = 6; e[17].flags = 0x12; e[17].tex = base + 0x150; e[17].mode = 4;
  e[17].x = lbl_803E11D8; e[17].y = lbl_803E11D8; e[17].z = lbl_803E11D8;
  e[18].layer = 6; e[18].flags = 0x12; e[18].tex = base + 0x150; e[18].mode = 2;
  e[18].x = lbl_803E1208; e[18].y = lbl_803E11F0; e[18].z = lbl_803E1208;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E11D8; buf.pos[1] = lbl_803E11D8; buf.pos[2] = lbl_803E11D8;
  buf.col[0] = lbl_803E11D8; buf.col[1] = lbl_803E11D8; buf.col[2] = lbl_803E11D8;
  buf.scale = lbl_803E11F0;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 0x12;
  buf.v5a = 0;
  buf.v5b = 0xc;
  buf.flags = 0x1000082;
  buf.count = (GfxCmd *)((u8 *)e + 0x1c8) - e;
  buf.hw[0] = *(s16 *)(base + 0x194); buf.hw[1] = *(s16 *)(base + 0x196);
  buf.hw[2] = *(s16 *)(base + 0x198); buf.hw[3] = *(s16 *)(base + 0x19a);
  buf.hw[4] = *(s16 *)(base + 0x19c); buf.hw[5] = *(s16 *)(base + 0x19e);
  buf.hw[6] = *(s16 *)(base + 0x1a0);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E11D8 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E11D8 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E11D8 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E11D8 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E11D8 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E11D8 + *(f32 *)(param_3 + 0x14);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,0x12,base,0x10,base + 0xb4,0x45,0);
}
#pragma scheduling reset
#pragma peephole reset


#pragma peephole off
#pragma scheduling off
void dll_92_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,f32 *param_6
                 )
{
  GfxBuf buf;
  GfxCmd *e;
  u8 *base = lbl_803171C0;
  f32 s = lbl_803E1210;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 5; e[0].tex = base + 0x60; e[0].mode = 4;
  e[0].x = lbl_803E1214; e[0].y = lbl_803E1214; e[0].z = lbl_803E1214;
  e[1].layer = 0; e[1].flags = 1; e[1].tex = lbl_803DB930; e[1].mode = 4;
  if (param_2 == 1) {
    e[1].x = lbl_803E1218;
  } else {
    e[1].x = lbl_803E121C;
  }
  e[1].y = lbl_803E1214; e[1].z = lbl_803E1214;
  e[2].layer = 0; e[2].flags = 6; e[2].tex = base + 0x54; e[2].mode = 2;
  if (param_2 == 1) {
    e[2].z = e[2].y = e[2].x = lbl_803E1220 * s;
  } else {
    e[2].z = e[2].y = e[2].x = lbl_803E1224 * s;
  }
  e[3].layer = 1; e[3].flags = 6; e[3].tex = base + 0x54; e[3].mode = 0x4000;
  e[3].x = lbl_803E1228; e[3].y = lbl_803E1210; e[3].z = lbl_803E1214;
  e[4].layer = 1; e[4].flags = 6; e[4].tex = base + 0x54; e[4].mode = 2;
  e[4].x = lbl_803E122C; e[4].y = lbl_803E122C; e[4].z = lbl_803E1230;
  e[5].layer = 2; e[5].flags = 6; e[5].tex = base + 0x54; e[5].mode = 0x4000;
  e[5].x = lbl_803E1228; e[5].y = lbl_803E1210; e[5].z = lbl_803E1214;
  e[6].layer = 2; e[6].flags = 6; e[6].tex = base + 0x54; e[6].mode = 2;
  e[6].x = lbl_803E1234; e[6].y = lbl_803E1234; e[6].z = lbl_803E1210;
  e[7].layer = 3; e[7].flags = 6; e[7].tex = base + 0x54; e[7].mode = 0x4000;
  e[7].x = lbl_803E1228; e[7].y = lbl_803E1210; e[7].z = lbl_803E1214;
  e[8].layer = 3; e[8].flags = 1; e[8].tex = lbl_803DB930; e[8].mode = 4;
  e[8].x = lbl_803E1214; e[8].y = lbl_803E1214; e[8].z = lbl_803E1214;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1214; buf.pos[1] = lbl_803E1214; buf.pos[2] = lbl_803E1214;
  buf.col[0] = lbl_803E1214; buf.col[1] = lbl_803E1214; buf.col[2] = lbl_803E1214;
  buf.scale = lbl_803E1238;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 6;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (GfxCmd *)((u8 *)e + 0xd8) - e;
  buf.hw[0] = *(s16 *)(base + 0x6c); buf.hw[1] = *(s16 *)(base + 0x6e);
  buf.hw[2] = *(s16 *)(base + 0x70); buf.hw[3] = *(s16 *)(base + 0x72);
  buf.hw[4] = *(s16 *)(base + 0x74); buf.hw[5] = *(s16 *)(base + 0x76);
  buf.hw[6] = *(s16 *)(base + 0x78);
  buf.cmds = buf.entries;
  buf.flags = 0x4000400;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0 && (uint)param_3 != 0) {
      buf.pos[0] = lbl_803E1214 + (*(f32 *)(param_1 + 0x18) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E1214 + (*(f32 *)(param_1 + 0x1c) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E1214 + (*(f32 *)(param_1 + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)param_1 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,6,base,4,base + 0x3c,0x3c,0);
}
#pragma scheduling reset
#pragma peephole reset
extern u8 lbl_80317260[];
extern undefined4 *gModgfxInterface;
extern f32 lbl_803E1240;
extern f32 lbl_803E1244;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1254;
extern f32 lbl_803E1258;


#pragma peephole off
#pragma scheduling off
void dll_93_func03(int param_1,int param_2,int param_3,uint param_4)
{
  GfxBuf buf;
  u8 *base = lbl_80317260;
  GfxCmd *e = buf.entries;
  f32 rval;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E1240; e[0].y = lbl_803E1240; e[0].z = lbl_803E1240;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = base + 0x1b0; e[1].mode = 2;
  rval = lbl_803E1248 * (f32)(int)randomGetRange(0, 10) + lbl_803E1244;
  e[1].x = rval; e[1].y = lbl_803E124C; e[1].z = rval;
  e[2].layer = 1; e[2].flags = 0x15; e[2].tex = base + 0x1b0; e[2].mode = 4;
  e[2].x = lbl_803E1250; e[2].y = lbl_803E1240; e[2].z = lbl_803E1240;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = base + 0x1b0; e[3].mode = 0x4000;
  e[3].x = lbl_803E1254; e[3].y = lbl_803E1240; e[3].z = lbl_803E1240;
  e[4].layer = 2; e[4].flags = 0x15; e[4].tex = base + 0x1b0; e[4].mode = 4;
  e[4].x = lbl_803E1240; e[4].y = lbl_803E1240; e[4].z = lbl_803E1240;
  e[5].layer = 2; e[5].flags = 0x15; e[5].tex = base + 0x1b0; e[5].mode = 0x4000;
  e[5].x = lbl_803E1254; e[5].y = lbl_803E1240; e[5].z = lbl_803E1240;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1240; buf.pos[1] = lbl_803E1240; buf.pos[2] = lbl_803E1240;
  buf.col[0] = lbl_803E1240; buf.col[1] = lbl_803E1240; buf.col[2] = lbl_803E1240;
  buf.scale = lbl_803E1258;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = (GfxCmd *)((u8 *)e + 0x90) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = buf.entries;
  buf.flags = 0xc0104c0;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E1240 + *(f32 *)(param_1 + 0xc);
      buf.pos[1] = lbl_803E1240 + *(f32 *)(param_1 + 0x10);
      buf.pos[2] = lbl_803E1240 + *(f32 *)(param_1 + 0x14);
    } else {
      buf.pos[0] = lbl_803E1240 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1240 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1240 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x89,0);
}
#pragma scheduling reset
#pragma peephole reset
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
extern f32 lbl_803E1318;
extern f32 lbl_803E131C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1340;
extern f32 lbl_803E1344;
extern f32 lbl_803E134C;
extern f32 lbl_803E1354;
extern f32 lbl_803E1358;
extern f32 lbl_803E135C;
extern f32 lbl_803E1360;
extern f32 lbl_803E1364;
extern f32 lbl_803E1368;
#pragma peephole off
#pragma scheduling off
void dll_94_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,f32 *param_6
                 )
{
  GfxBuf buf;
  GfxCmd *e;
  u8 *base = lbl_80317488;
  f32 s = lbl_803E1268;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 5; e[0].tex = base + 0x60; e[0].mode = 4;
  e[0].x = lbl_803E126C; e[0].y = lbl_803E126C; e[0].z = lbl_803E126C;
  e[1].layer = 0; e[1].flags = 1; e[1].tex = lbl_803DB938; e[1].mode = 4;
  if (param_2 == 1) {
    e[1].x = lbl_803E1270;
  } else {
    e[1].x = lbl_803E1274;
  }
  e[1].y = lbl_803E126C; e[1].z = lbl_803E126C;
  e[2].layer = 0; e[2].flags = 6; e[2].tex = base + 0x54; e[2].mode = 2;
  if (param_2 == 1) {
    e[2].z = e[2].y = e[2].x = lbl_803E1278 * s;
  } else {
    e[2].z = e[2].y = e[2].x = lbl_803E127C * s;
  }
  e[3].layer = 1; e[3].flags = 6; e[3].tex = base + 0x54; e[3].mode = 0x4000;
  e[3].x = lbl_803E1280; e[3].y = lbl_803E1268; e[3].z = lbl_803E126C;
  e[4].layer = 1; e[4].flags = 6; e[4].tex = base + 0x54; e[4].mode = 2;
  e[4].x = lbl_803E1284; e[4].y = lbl_803E1284; e[4].z = lbl_803E1288;
  e[5].layer = 2; e[5].flags = 6; e[5].tex = base + 0x54; e[5].mode = 0x4000;
  e[5].x = lbl_803E1280; e[5].y = lbl_803E1268; e[5].z = lbl_803E126C;
  e[6].layer = 2; e[6].flags = 6; e[6].tex = base + 0x54; e[6].mode = 2;
  e[6].x = lbl_803E128C; e[6].y = lbl_803E128C; e[6].z = lbl_803E1268;
  e[7].layer = 3; e[7].flags = 6; e[7].tex = base + 0x54; e[7].mode = 0x4000;
  e[7].x = lbl_803E1280; e[7].y = lbl_803E1268; e[7].z = lbl_803E126C;
  e[8].layer = 3; e[8].flags = 1; e[8].tex = lbl_803DB938; e[8].mode = 4;
  e[8].x = lbl_803E126C; e[8].y = lbl_803E126C; e[8].z = lbl_803E126C;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E126C; buf.pos[1] = lbl_803E126C; buf.pos[2] = lbl_803E126C;
  buf.col[0] = lbl_803E126C; buf.col[1] = lbl_803E126C; buf.col[2] = lbl_803E126C;
  buf.scale = lbl_803E1290;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 6;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (GfxCmd *)((u8 *)e + 0xd8) - e;
  buf.hw[0] = *(s16 *)(base + 0x6c); buf.hw[1] = *(s16 *)(base + 0x6e);
  buf.hw[2] = *(s16 *)(base + 0x70); buf.hw[3] = *(s16 *)(base + 0x72);
  buf.hw[4] = *(s16 *)(base + 0x74); buf.hw[5] = *(s16 *)(base + 0x76);
  buf.hw[6] = *(s16 *)(base + 0x78);
  buf.cmds = buf.entries;
  buf.flags = 0x4000410;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0 && (uint)param_3 != 0) {
      buf.pos[0] = lbl_803E126C + (*(f32 *)(param_1 + 0x18) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E126C + (*(f32 *)(param_1 + 0x1c) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E126C + (*(f32 *)(param_1 + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)param_1 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,6,base,4,base + 0x3c,0x3c,0);
}
#pragma scheduling reset
#pragma peephole reset
extern u8 lbl_80317528[];
extern u8 lbl_803175E8[];
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
extern f32 lbl_803E12C8;
extern f32 lbl_803E12CC;
extern f32 lbl_803E12D0;
extern f32 lbl_803E12D4;
extern f32 lbl_803E12D8;
#pragma peephole off
#pragma scheduling off
void dll_95_func03(int param_1,int param_2,int param_3)
{
  GfxBuf buf;
  u8 *base = lbl_80317528;
  GfxCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 8; e[0].tex = base + 0x80; e[0].mode = 2;
  e[0].x = lbl_803E1298; e[0].y = lbl_803E129C; e[0].z = lbl_803E1298;
  e[1].layer = 0; e[1].flags = 4; e[1].tex = lbl_803DB940; e[1].mode = 8;
  e[1].x = lbl_803E12A0; e[1].y = lbl_803E12A0; e[1].z = lbl_803E12A4;
  e[2].layer = 0; e[2].flags = 4; e[2].tex = base + 0x80; e[2].mode = 8;
  e[2].x = lbl_803E12A0; e[2].y = lbl_803E12A8; e[2].z = lbl_803E12A4;
  e[3].layer = 0; e[3].flags = 0; e[3].tex = (void *)0; e[3].mode = 0x400000;
  e[3].x = lbl_803E12A4; e[3].y = lbl_803E12AC; e[3].z = lbl_803E12A4;
  e[4].layer = 1; e[4].flags = 8; e[4].tex = base + 0x80; e[4].mode = 2;
  e[4].x = lbl_803E12B0; e[4].y = lbl_803E12B0; e[4].z = lbl_803E12B0;
  e[5].layer = 1; e[5].flags = 0; e[5].tex = (void *)0; e[5].mode = 0x400000;
  e[5].x = lbl_803E12A4; e[5].y = lbl_803E12B4; e[5].z = lbl_803E12A4;
  e[6].layer = 2; e[6].flags = 8; e[6].tex = base + 0x80; e[6].mode = 4;
  e[6].x = lbl_803E12A4; e[6].y = lbl_803E12A4; e[6].z = lbl_803E12A4;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E12A4; buf.pos[1] = lbl_803E12A4; buf.pos[2] = lbl_803E12A4;
  buf.col[0] = lbl_803E12A4; buf.col[1] = lbl_803E12A4; buf.col[2] = lbl_803E12A4;
  buf.scale = lbl_803E12B8;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 8;
  buf.v5a = 0;
  buf.v5b = 0x3c;
  buf.count = (GfxCmd *)((u8 *)e + 0xa8) - e;
  buf.hw[0] = *(s16 *)(base + 0x90); buf.hw[1] = *(s16 *)(base + 0x92);
  buf.hw[2] = *(s16 *)(base + 0x94); buf.hw[3] = *(s16 *)(base + 0x96);
  buf.hw[4] = *(s16 *)(base + 0x98); buf.hw[5] = *(s16 *)(base + 0x9a);
  buf.hw[6] = *(s16 *)(base + 0x9c);
  buf.cmds = e;
  buf.flags = 0x4002400;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0 && (uint)param_3 != 0) {
      buf.pos[0] = lbl_803E12A4 + (*(f32 *)(param_1 + 0x18) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E12A4 + (*(f32 *)(param_1 + 0x1c) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E12A4 + (*(f32 *)(param_1 + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)param_1 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,8,base,8,base + 0x50,0x46,0);
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
#pragma scheduling off
int dll_96_func03(int param_1,int param_2,int param_3,uint param_4)
{
  GfxBuf buf;
  u8 *base = lbl_803175E8;
  GfxCmd *e;

  if (GameBit_Get(0x63c) != 0) {
    return -1;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E12C0; e[0].y = lbl_803E12C0; e[0].z = lbl_803E12C0;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = base + 0x1b0; e[1].mode = 2;
  if (GameBit_Get(0x4e9) != 0) {
    e[1].x = lbl_803E12C4;
  } else {
    e[1].x = lbl_803E12C8 * (f32)(int)randomGetRange(5, 10);
  }
  e[1].y = lbl_803E12CC;
  e[1].z = e[1].x;
  e[2].layer = 1; e[2].flags = 7; e[2].tex = base + 0x164; e[2].mode = 2;
  e[2].x = lbl_803E12D0; e[2].y = lbl_803E12D4; e[2].z = lbl_803E12D0;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = base + 0x1b0; e[3].mode = 4;
  e[3].x = lbl_803E12D8; e[3].y = lbl_803E12C0; e[3].z = lbl_803E12C0;
  e[4].layer = 1; e[4].flags = 0x15; e[4].tex = base + 0x1b0; e[4].mode = 0x4000;
  e[4].x = lbl_803E12C0; e[4].y = lbl_803E12D0; e[4].z = lbl_803E12C0;
  e[5].layer = 2; e[5].flags = 0x15; e[5].tex = base + 0x1b0; e[5].mode = 4;
  e[5].x = lbl_803E12C0; e[5].y = lbl_803E12C0; e[5].z = lbl_803E12C0;
  e[6].layer = 2; e[6].flags = 0x15; e[6].tex = base + 0x1b0; e[6].mode = 0x4000;
  e[6].x = lbl_803E12C0; e[6].y = lbl_803E12D0; e[6].z = lbl_803E12C0;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E12C0; buf.pos[1] = lbl_803E12C0; buf.pos[2] = lbl_803E12C0;
  buf.col[0] = lbl_803E12C0; buf.col[1] = lbl_803E12C0; buf.col[2] = lbl_803E12C0;
  buf.scale = lbl_803E12D0;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (GfxCmd *)((u8 *)e + 0xa8) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = buf.entries;
  buf.flags = 0xc0104c0;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E12C0 + *(f32 *)(param_1 + 0xc);
      buf.pos[1] = lbl_803E12C0 + *(f32 *)(param_1 + 0x10);
      buf.pos[2] = lbl_803E12C0 + *(f32 *)(param_1 + 0x14);
    } else {
      buf.pos[0] = lbl_803E12C0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E12C0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E12C0 + *(f32 *)(param_3 + 0x14);
    }
  }
  return (**(int (**)(GfxBuf *, int, int, u8 *, int, u8 *, int, int))(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x89,0);
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
#pragma scheduling off
void dll_97_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,f32 *param_6
                 )
{
  GfxBuf buf;
  GfxCmd *e;
  u8 *base = lbl_80317810;
  f32 s = lbl_803E12E8;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 5; e[0].tex = base + 0x60; e[0].mode = 4;
  e[0].x = lbl_803E12EC; e[0].y = lbl_803E12EC; e[0].z = lbl_803E12EC;
  e[1].layer = 0; e[1].flags = 1; e[1].tex = lbl_803DB948; e[1].mode = 4;
  if (param_2 == 1) {
    e[1].x = lbl_803E12F0;
  } else {
    e[1].x = lbl_803E12F4;
  }
  e[1].y = lbl_803E12EC; e[1].z = lbl_803E12EC;
  e[2].layer = 0; e[2].flags = 6; e[2].tex = base + 0x54; e[2].mode = 2;
  if (param_2 == 1) {
    e[2].z = e[2].y = e[2].x = lbl_803E12F8 * s;
  } else {
    e[2].z = e[2].y = e[2].x = lbl_803E12FC * s;
  }
  e[3].layer = 1; e[3].flags = 6; e[3].tex = base + 0x54; e[3].mode = 0x4000;
  e[3].x = lbl_803E1300; e[3].y = lbl_803E12E8; e[3].z = lbl_803E12EC;
  e[4].layer = 1; e[4].flags = 6; e[4].tex = base + 0x54; e[4].mode = 2;
  e[4].x = lbl_803E1304; e[4].y = lbl_803E1304; e[4].z = lbl_803E1308;
  e[5].layer = 2; e[5].flags = 6; e[5].tex = base + 0x54; e[5].mode = 0x4000;
  e[5].x = lbl_803E1300; e[5].y = lbl_803E12E8; e[5].z = lbl_803E12EC;
  e[6].layer = 2; e[6].flags = 6; e[6].tex = base + 0x54; e[6].mode = 2;
  e[6].x = lbl_803E130C; e[6].y = lbl_803E130C; e[6].z = lbl_803E12E8;
  e[7].layer = 3; e[7].flags = 6; e[7].tex = base + 0x54; e[7].mode = 0x4000;
  e[7].x = lbl_803E1300; e[7].y = lbl_803E12E8; e[7].z = lbl_803E12EC;
  e[8].layer = 3; e[8].flags = 1; e[8].tex = lbl_803DB948; e[8].mode = 4;
  e[8].x = lbl_803E12EC; e[8].y = lbl_803E12EC; e[8].z = lbl_803E12EC;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E12EC; buf.pos[1] = lbl_803E12EC; buf.pos[2] = lbl_803E12EC;
  buf.col[0] = lbl_803E12EC; buf.col[1] = lbl_803E12EC; buf.col[2] = lbl_803E12EC;
  buf.scale = lbl_803E1310;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 6;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (GfxCmd *)((u8 *)e + 0xd8) - e;
  buf.hw[0] = *(s16 *)(base + 0x6c); buf.hw[1] = *(s16 *)(base + 0x6e);
  buf.hw[2] = *(s16 *)(base + 0x70); buf.hw[3] = *(s16 *)(base + 0x72);
  buf.hw[4] = *(s16 *)(base + 0x74); buf.hw[5] = *(s16 *)(base + 0x76);
  buf.hw[6] = *(s16 *)(base + 0x78);
  buf.cmds = buf.entries;
  buf.flags = 0x4000410;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0 && (uint)param_3 != 0) {
      buf.pos[0] = lbl_803E12EC + (*(f32 *)(param_1 + 0x18) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E12EC + (*(f32 *)(param_1 + 0x1c) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E12EC + (*(f32 *)(param_1 + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)param_1 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,6,base,4,base + 0x3c,0x3c,0);
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
#pragma scheduling off
void dll_98_func03(int param_1,int param_2,int param_3,uint param_4,int param_5,int param_6)
{
  GfxBuf buf;
  u8 *base = lbl_803178B0;
  GfxCmd *e;

  *(s16 *)(base + 0x216) = randomGetRange(0, 0x1e) + 0x1e;
  *(s16 *)(base + 0x218) = *(s16 *)(base + 0x216);
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0x12; e[0].tex = base + 0x1dc; e[0].mode = 4;
  e[0].x = lbl_803E1318; e[0].y = lbl_803E1318; e[0].z = lbl_803E1318;
  e[1].layer = 0; e[1].flags = 0x12; e[1].tex = base + 0x1dc; e[1].mode = 2;
  e[1].z = e[1].x = lbl_803E131C; e[1].y = lbl_803E1320;
  e[2].layer = 1; e[2].flags = 0x12; e[2].tex = base + 0x1dc; e[2].mode = 4;
  e[2].x = lbl_803E1324; e[2].y = lbl_803E1318; e[2].z = lbl_803E1318;
  e[3].layer = 1; e[3].flags = 0x12; e[3].tex = base + 0x1dc; e[3].mode = 0x400000;
  e[3].x = lbl_803E1318;
  if ((uint)param_6 != 0) {
    e[3].y = lbl_803E1328;
  } else {
    e[3].y = lbl_803E132C;
  }
  e[3].z = lbl_803E1318;
  e[4].layer = 1; e[4].flags = 0x12; e[4].tex = base + 0x1dc; e[4].mode = 0x4000;
  e[4].x = lbl_803E1318;
  if ((uint)param_6 != 0) {
    e[4].y = lbl_803E1330;
  } else {
    e[4].y = lbl_803E1334;
  }
  e[4].z = lbl_803E1318;
  e[5].layer = 2; e[5].flags = 0x12; e[5].tex = base + 0x1dc; e[5].mode = 4;
  e[5].x = lbl_803E1318; e[5].y = lbl_803E1318; e[5].z = lbl_803E1318;
  e[6].layer = 2; e[6].flags = 0x12; e[6].tex = base + 0x1dc; e[6].mode = 0x400000;
  e[6].x = lbl_803E1318;
  if ((uint)param_6 != 0) {
    e[6].y = lbl_803E1328;
  } else {
    e[6].y = lbl_803E132C;
  }
  e[6].z = lbl_803E1318;
  e[7].layer = 2; e[7].flags = 0x12; e[7].tex = base + 0x1dc; e[7].mode = 0x4000;
  e[7].x = lbl_803E1318;
  if ((uint)param_6 != 0) {
    e[7].y = lbl_803E1330;
  } else {
    e[7].y = lbl_803E1334;
  }
  e[7].z = lbl_803E1318;
  e[8].layer = 2; e[8].flags = 0x12; e[8].tex = base + 0x1dc; e[8].mode = 2;
  e[8].x = lbl_803E1330; e[8].y = lbl_803E1330; e[8].z = lbl_803E1330;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1318;
  if ((uint)param_6 != 0) {
    buf.pos[1] = lbl_803E1338;
  } else {
    buf.pos[1] = lbl_803E133C;
  }
  buf.pos[2] = lbl_803E1318;
  buf.col[0] = lbl_803E1318; buf.col[1] = lbl_803E1318; buf.col[2] = lbl_803E1318;
  buf.scale = lbl_803E1330;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 0x12;
  buf.v5a = 0;
  buf.v5b = 0x10;
  buf.flags = 0x4080400;
  buf.count = (GfxCmd *)((u8 *)e + 0xd8) - e;
  buf.hw[0] = *(s16 *)(base + 0x214); buf.hw[1] = *(s16 *)(base + 0x216);
  buf.hw[2] = *(s16 *)(base + 0x218); buf.hw[3] = *(s16 *)(base + 0x21a);
  buf.hw[4] = *(s16 *)(base + 0x21c); buf.hw[5] = *(s16 *)(base + 0x21e);
  buf.hw[6] = *(s16 *)(base + 0x220);
  buf.cmds = buf.entries;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)buf.ctx != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] = lbl_803E1318 + *(f32 *)(buf.ctx + 0x20);
    } else {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1318 + *(f32 *)(param_3 + 0x14);
    }
  }
  {
    int v;
    if (param_2 == 0) {
      v = 0x3e9;
    } else if (param_2 == 1) {
      v = 0x3f0;
    } else {
      v = 0x3f3;
    }
    (**(code **)(*gModgfxInterface + 8))(&buf,0,0x12,(uint)param_6 != 0 ? base + 0xb4 : base,0x10,base + 0x168,v,0);
  }
}
#pragma scheduling reset
#pragma peephole reset
#pragma peephole off
#pragma scheduling off
void dll_99_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,f32 *param_6
                 )
{
  GfxBuf buf;
  GfxCmd *e;
  u8 *base = lbl_80317AF8;
  f32 s = lbl_803E1340;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 5; e[0].tex = base + 0x60; e[0].mode = 4;
  e[0].x = lbl_803E1344; e[0].y = lbl_803E1344; e[0].z = lbl_803E1344;
  e[1].layer = 0; e[1].flags = 1; e[1].tex = lbl_803DB950; e[1].mode = 4;
  if (param_2 == 1) {
    e[1].x = lbl_803E1348;
  } else {
    e[1].x = lbl_803E134C;
  }
  e[1].y = lbl_803E1344; e[1].z = lbl_803E1344;
  e[2].layer = 0; e[2].flags = 6; e[2].tex = base + 0x54; e[2].mode = 2;
  if (param_2 == 1) {
    e[2].z = e[2].y = e[2].x = lbl_803E1350 * s;
  } else {
    e[2].z = e[2].y = e[2].x = lbl_803E1354 * s;
  }
  e[3].layer = 1; e[3].flags = 6; e[3].tex = base + 0x54; e[3].mode = 0x4000;
  e[3].x = lbl_803E1358; e[3].y = lbl_803E1340; e[3].z = lbl_803E1344;
  e[4].layer = 1; e[4].flags = 6; e[4].tex = base + 0x54; e[4].mode = 2;
  e[4].x = lbl_803E135C; e[4].y = lbl_803E135C; e[4].z = lbl_803E1360;
  e[5].layer = 2; e[5].flags = 6; e[5].tex = base + 0x54; e[5].mode = 0x4000;
  e[5].x = lbl_803E1358; e[5].y = lbl_803E1340; e[5].z = lbl_803E1344;
  e[6].layer = 2; e[6].flags = 6; e[6].tex = base + 0x54; e[6].mode = 2;
  e[6].x = lbl_803E1364; e[6].y = lbl_803E1364; e[6].z = lbl_803E1340;
  e[7].layer = 3; e[7].flags = 6; e[7].tex = base + 0x54; e[7].mode = 0x4000;
  e[7].x = lbl_803E1358; e[7].y = lbl_803E1340; e[7].z = lbl_803E1344;
  e[8].layer = 3; e[8].flags = 1; e[8].tex = lbl_803DB950; e[8].mode = 4;
  e[8].x = lbl_803E1344; e[8].y = lbl_803E1344; e[8].z = lbl_803E1344;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1344; buf.pos[1] = lbl_803E1344; buf.pos[2] = lbl_803E1344;
  buf.col[0] = lbl_803E1344; buf.col[1] = lbl_803E1344; buf.col[2] = lbl_803E1344;
  buf.scale = lbl_803E1368;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 6;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (GfxCmd *)((u8 *)e + 0xd8) - e;
  buf.hw[0] = *(s16 *)(base + 0x6c); buf.hw[1] = *(s16 *)(base + 0x6e);
  buf.hw[2] = *(s16 *)(base + 0x70); buf.hw[3] = *(s16 *)(base + 0x72);
  buf.hw[4] = *(s16 *)(base + 0x74); buf.hw[5] = *(s16 *)(base + 0x76);
  buf.hw[6] = *(s16 *)(base + 0x78);
  buf.cmds = buf.entries;
  buf.flags = 0x4000410;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0 && (uint)param_3 != 0) {
      buf.pos[0] = lbl_803E1344 + (*(f32 *)(param_1 + 0x18) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E1344 + (*(f32 *)(param_1 + 0x1c) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E1344 + (*(f32 *)(param_1 + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)param_1 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,6,base,4,base + 0x3c,0x3c,0);
}
#pragma scheduling reset
#pragma peephole reset
