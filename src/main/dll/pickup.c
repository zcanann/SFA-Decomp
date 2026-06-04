#include "ghidra_import.h"
#include "main/dll/pickup.h"

extern undefined4 FUN_80286838();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_80318c88;
extern undefined4 DAT_80318d5c;
extern undefined DAT_80318dec;
extern undefined DAT_80318dfc;
extern undefined DAT_80318e0c;
extern undefined DAT_80318e38;
extern u8 lbl_80318038[];
extern undefined4 DAT_80318e80;
extern undefined4 DAT_80318e82;
extern undefined4 DAT_80318e84;
extern undefined4 DAT_80318e86;
extern undefined4 DAT_80318e88;
extern undefined4 DAT_80318e8a;
extern undefined4 DAT_80318e8c;
extern undefined4 DAT_80318eb0;
extern undefined4 DAT_80318f84;
extern undefined DAT_80319024;
extern undefined DAT_80319060;
extern undefined4 DAT_803190a8;
extern undefined4 DAT_803190aa;
extern undefined4 DAT_803190ac;
extern undefined4 DAT_803190ae;
extern undefined4 DAT_803190b0;
extern undefined4 DAT_803190b2;
extern undefined4 DAT_803190b4;
extern undefined4 DAT_803190d8;
extern undefined DAT_80319168;
extern undefined4 DAT_803191ac;
extern undefined4 DAT_8031923c;
extern undefined4 DAT_8031924c;
extern undefined4 DAT_8031925c;
extern undefined DAT_80319288;
extern undefined4 DAT_803192d0;
extern undefined4 DAT_803192d2;
extern undefined4 DAT_803192d4;
extern undefined4 DAT_803192d6;
extern undefined4 DAT_803192d8;
extern undefined4 DAT_803192da;
extern undefined4 DAT_803192dc;
extern undefined DAT_80319318;
extern undefined DAT_80319344;
extern undefined4 DAT_80319300;
extern undefined4 DAT_803193d4;
extern undefined DAT_80319474;
extern undefined DAT_80319484;
extern undefined DAT_803194b0;
extern undefined4 DAT_803194f8;
extern undefined4 DAT_803194fa;
extern undefined4 DAT_803194fc;
extern undefined4 DAT_803194fe;
extern undefined4 DAT_80319500;
extern undefined4 DAT_80319502;
extern undefined4 DAT_80319504;
extern undefined4 DAT_80319528;
extern undefined4 DAT_803195fc;
extern undefined DAT_803196d8;
extern undefined4 DAT_80319720;
extern undefined4 DAT_80319722;
extern undefined4 DAT_80319724;
extern undefined4 DAT_80319726;
extern undefined4 DAT_80319728;
extern undefined4 DAT_8031972a;
extern undefined4 DAT_8031972c;
extern undefined4 DAT_80319750;
extern undefined4 DAT_80319824;
extern undefined DAT_803198b4;
extern undefined DAT_803198c4;
extern undefined DAT_803198d4;
extern undefined DAT_80319900;
extern undefined4 DAT_80319948;
extern undefined4 DAT_8031994a;
extern undefined4 DAT_8031994c;
extern undefined4 DAT_8031994e;
extern undefined4 DAT_80319950;
extern undefined4 DAT_80319952;
extern undefined4 DAT_80319954;
extern undefined4 DAT_80319998;
extern undefined4 DAT_803199e8;
extern undefined DAT_80319a00;
extern undefined4 DAT_80319a10;
extern undefined4 DAT_80319a12;
extern undefined4 DAT_80319a14;
extern undefined4 DAT_80319a16;
extern undefined4 DAT_80319a18;
extern undefined4 DAT_80319a1a;
extern undefined4 DAT_80319a1c;
extern undefined4 DAT_80319a40;
extern undefined4 DAT_80319a60;
extern undefined4 DAT_80319a62;
extern undefined4 DAT_80319a64;
extern undefined4 DAT_80319a66;
extern undefined4 DAT_80319a68;
extern undefined4 DAT_80319a6a;
extern undefined4 DAT_80319a6c;
extern undefined4 DAT_80319a90;
extern undefined4 DAT_80319ae0;
extern undefined DAT_80319af8;
extern undefined4 DAT_80319b08;
extern undefined4 DAT_80319b0a;
extern undefined4 DAT_80319b0c;
extern undefined4 DAT_80319b0e;
extern undefined4 DAT_80319b10;
extern undefined4 DAT_80319b12;
extern undefined4 DAT_80319b14;
extern undefined4 DAT_80319b38;
extern undefined4 DAT_80319bc4;
extern undefined DAT_80319c0c;
extern undefined DAT_80319c1c;
extern undefined DAT_80319c2c;
extern undefined4 DAT_80319c48;
extern undefined4 DAT_80319c4a;
extern undefined4 DAT_80319c4c;
extern undefined4 DAT_80319c4e;
extern undefined4 DAT_80319c50;
extern undefined4 DAT_80319c52;
extern undefined4 DAT_80319c54;
extern undefined4 DAT_80319c78;
extern undefined4 DAT_80319d04;
extern undefined DAT_80319d4c;
extern undefined DAT_80319d5c;
extern undefined DAT_80319d6c;
extern undefined4 DAT_80319d88;
extern undefined4 DAT_80319d8a;
extern undefined4 DAT_80319d8c;
extern undefined4 DAT_80319d8e;
extern undefined4 DAT_80319d90;
extern undefined4 DAT_80319d92;
extern undefined4 DAT_80319d94;
extern undefined DAT_803dc5d0;
extern undefined DAT_803dc5d8;
extern undefined4 DAT_803dc5e0;
extern undefined DAT_803dc5e8;
extern undefined4* gModgfxInterface;
extern f64 DOUBLE_803e2100;
extern f64 DOUBLE_803e21a8;
extern f64 DOUBLE_803e21e8;
extern f64 DOUBLE_803e2210;
extern f32 lbl_803E2078;
extern f32 lbl_803E1600;
extern f32 lbl_803E1604;
extern f32 lbl_803E1608;
extern f32 lbl_803E160C;
extern f32 lbl_803E1610;
extern f32 lbl_803E1614;
extern f32 lbl_803E1618;
extern f32 lbl_803E161C;
extern f32 lbl_803E1620;
extern f32 lbl_803E1624;
extern f32 lbl_803E207C;
extern f32 lbl_803E2080;
extern f32 lbl_803E2084;
extern f32 lbl_803E2088;
extern f32 lbl_803E208C;
extern f32 lbl_803E2090;
extern f32 lbl_803E2094;
extern f32 lbl_803E2098;
extern f32 lbl_803E209C;
extern f32 lbl_803E20A0;
extern f32 lbl_803E20A4;
extern f32 lbl_803E20A8;
extern f32 lbl_803E20AC;
extern f32 lbl_803E20B0;
extern f32 lbl_803E20B4;
extern f32 lbl_803E20B8;
extern f32 lbl_803E20BC;
extern f32 lbl_803E20C0;
extern f32 lbl_803E20C8;
extern f32 lbl_803E20CC;
extern f32 lbl_803E20D0;
extern f32 lbl_803E20D4;
extern f32 lbl_803E20D8;
extern f32 lbl_803E20DC;
extern f32 lbl_803E20E0;
extern f32 lbl_803E20E4;
extern f32 lbl_803E20E8;
extern f32 lbl_803E20EC;
extern f32 lbl_803E20F0;
extern f32 lbl_803E20F4;
extern f32 lbl_803E20F8;
extern f32 lbl_803E20FC;
extern f32 lbl_803E2108;
extern f32 lbl_803E210C;
extern f32 lbl_803E2110;
extern f32 lbl_803E2114;
extern f32 lbl_803E2118;
extern f32 lbl_803E211C;
extern f32 lbl_803E2120;
extern f32 lbl_803E2124;
extern f32 lbl_803E2128;
extern f32 lbl_803E212C;
extern f32 lbl_803E2130;
extern f32 lbl_803E2138;
extern f32 lbl_803E213C;
extern f32 lbl_803E2140;
extern f32 lbl_803E2144;
extern f32 lbl_803E2148;
extern f32 lbl_803E214C;
extern f32 lbl_803E2150;
extern f32 lbl_803E2154;
extern f32 lbl_803E2158;
extern f32 lbl_803E215C;
extern f32 lbl_803E2160;
extern f32 lbl_803E2164;
extern f32 lbl_803E2168;
extern f32 lbl_803E216C;
extern f32 lbl_803E2170;
extern f32 lbl_803E2174;
extern f32 lbl_803E2178;
extern f32 lbl_803E217C;
extern f32 lbl_803E2180;
extern f32 lbl_803E2188;
extern f32 lbl_803E218C;
extern f32 lbl_803E2190;
extern f32 lbl_803E2194;
extern f32 lbl_803E2198;
extern f32 lbl_803E219C;
extern f32 lbl_803E21A0;
extern f32 lbl_803E21A4;
extern f32 lbl_803E21B0;
extern f32 lbl_803E21B4;
extern f32 lbl_803E21B8;
extern f32 lbl_803E21BC;
extern f32 lbl_803E21C0;
extern f32 lbl_803E21C4;
extern f32 lbl_803E21C8;
extern f32 lbl_803E21CC;
extern f32 lbl_803E21D0;
extern f32 lbl_803E21D4;
extern f32 lbl_803E21D8;
extern f32 lbl_803E21DC;
extern f32 lbl_803E21E0;
extern f32 lbl_803E21E4;
extern f32 lbl_803E21F0;
extern f32 lbl_803E21F4;
extern f32 lbl_803E21F8;
extern f32 lbl_803E21FC;
extern f32 lbl_803E2200;
extern f32 lbl_803E2204;
extern f32 lbl_803E2208;
extern f32 lbl_803E2218;
extern f32 lbl_803E221C;
extern f32 lbl_803E2220;
extern f32 lbl_803E2224;
extern f32 lbl_803E2228;
extern f32 lbl_803E222C;
extern f32 lbl_803E2230;
extern f32 lbl_803E2234;
extern f32 lbl_803E2238;
extern f32 lbl_803E223C;
extern f32 lbl_803E2240;
extern f32 lbl_803E2244;
extern f32 lbl_803E2248;
extern f32 lbl_803E2250;
extern f32 lbl_803E2254;
extern f32 lbl_803E2258;
extern f32 lbl_803E225C;
extern f32 lbl_803E2260;
extern f32 lbl_803E2264;
extern f32 lbl_803E2268;
extern f32 lbl_803E226C;
extern f32 lbl_803E2270;
extern f32 lbl_803E2274;
extern f32 lbl_803E2278;
extern f32 lbl_803E227C;

/*
 * --INFO--
 *
 * Function: dll_9D_func03
 * EN v1.0 Address: 0x800FD744
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FD9E0
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
typedef struct {
  u32 mode;       /* +0x00 */
  f32 x, y, z;    /* +0x04 +0x08 +0x0c */
  void *tex;      /* +0x10 */
  u16 flags;      /* +0x14 */
  u8 layer;       /* +0x16 */
} GfxCmd;

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
  u8 v58, v59, v5a, v5b, v5c, count;  /* +0x58..+0x5d */
  u8 pad1[2];     /* +0x5e */
  GfxCmd entries[32];  /* +0x60 */
} GfxBuf;

extern f32 lbl_803E13F8;
extern f32 lbl_803E13FC;
extern f32 lbl_803E1400;
extern f32 lbl_803E1404;
extern f32 lbl_803E1408;
extern f32 lbl_803E140C;
extern f32 lbl_803E1410;
extern f32 lbl_803E1414;
void dll_9D_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4)
{
  GfxBuf buf;
  u8 *tab = lbl_80318038;
  GfxCmd *e = buf.entries;
  GfxCmd *end;
  u32 fl;

  e[0].layer = 0;  e[0].flags = 0x15; e[0].tex = &tab[432]; e[0].mode = 4;
  e[0].x = lbl_803E13F8; e[0].y = lbl_803E13F8; e[0].z = lbl_803E13F8;
  e[1].layer = 0;  e[1].flags = 7;    e[1].tex = &tab[356]; e[1].mode = 2;
  e[1].x = lbl_803E13FC; e[1].y = lbl_803E1400; e[1].z = lbl_803E13FC;
  e[2].layer = 0;  e[2].flags = 7;    e[2].tex = &tab[372]; e[2].mode = 2;
  e[2].x = lbl_803E1400; e[2].y = lbl_803E1400; e[2].z = lbl_803E1400;
  e[3].layer = 0;  e[3].flags = 7;    e[3].tex = &tab[388]; e[3].mode = 2;
  e[3].x = lbl_803E13FC; e[3].y = lbl_803E1400; e[3].z = lbl_803E13FC;
  e[4].layer = 0;  e[4].flags = 0;    e[4].tex = (void *)0;          e[4].mode = 0x400000;
  e[4].x = lbl_803E13F8; e[4].y = lbl_803E1404; e[4].z = lbl_803E13F8;
  e[5].layer = 1;  e[5].flags = 7;    e[5].tex = &tab[372]; e[5].mode = 4;
  e[5].x = lbl_803E1408; e[5].y = lbl_803E13F8; e[5].z = lbl_803E13F8;
  e[6].layer = 1;  e[6].flags = 0x15; e[6].tex = &tab[432]; e[6].mode = 0x4000;
  e[6].x = lbl_803E13F8; e[6].y = lbl_803E13F8; e[6].z = lbl_803E13F8;
  e[7].layer = 1;  e[7].flags = 0;    e[7].tex = (void *)0;          e[7].mode = 0x400000;
  e[7].x = lbl_803E13F8; e[7].y = lbl_803E140C; e[7].z = lbl_803E13F8;
  e[8].layer = 2;  e[8].flags = 0x15; e[8].tex = &tab[432]; e[8].mode = 0x4000;
  e[8].x = lbl_803E13F8; e[8].y = lbl_803E13F8; e[8].z = lbl_803E13F8;
  e[9].layer = 2;  e[9].flags = 0;    e[9].tex = (void *)0;          e[9].mode = 0x400000;
  e[9].x = lbl_803E13F8; e[9].y = lbl_803E1410; e[9].z = lbl_803E13F8;
  e[10].layer = 3; e[10].flags = 0x15; e[10].tex = &tab[432]; e[10].mode = 0x4000;
  e[10].x = lbl_803E13F8; e[10].y = lbl_803E13F8; e[10].z = lbl_803E13F8;
  e[11].layer = 3; e[11].flags = 0;    e[11].tex = (void *)0;          e[11].mode = 0x400000;
  e[11].x = lbl_803E13F8; e[11].y = lbl_803E140C; e[11].z = lbl_803E13F8;
  e[12].layer = 3; e[12].flags = 7;    e[12].tex = &tab[372]; e[12].mode = 4;
  e[12].x = lbl_803E13F8; e[12].y = lbl_803E13F8; e[12].z = lbl_803E13F8;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E13F8; buf.pos[1] = lbl_803E13F8; buf.pos[2] = lbl_803E13F8;
  buf.col[0] = lbl_803E13F8; buf.col[1] = lbl_803E13F8; buf.col[2] = lbl_803E13F8;
  buf.scale = lbl_803E1414;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  end = e + 13;
  buf.count = end - e;
  buf.hw[0] = *(s16 *)&tab[504]; buf.hw[1] = *(s16 *)&tab[506];
  buf.hw[2] = *(s16 *)&tab[508]; buf.hw[3] = *(s16 *)&tab[510];
  buf.hw[4] = *(s16 *)&tab[512]; buf.hw[5] = *(s16 *)&tab[514];
  buf.hw[6] = *(s16 *)&tab[516];
  buf.cmds = e;
  fl = 0xc0100c0;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E13F8 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E13F8 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E13F8 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E13F8 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E13F8 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E13F8 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[212],0x46c,0);
}

/*
 * --INFO--
 *
 * Function: dll_9E_func03
 * EN v1.0 Address: 0x800FDA98
 * EN v1.0 Size: 888b
 */
extern u8 lbl_80318260[];
extern f32 lbl_803E1418;
extern f32 lbl_803E141C;
extern f32 lbl_803E1420;
extern f32 lbl_803E1424;
extern f32 lbl_803E1428;
extern f32 lbl_803E142C;
extern f32 lbl_803E1430;
extern f32 lbl_803E1434;
extern f32 lbl_803E1438;
extern f32 lbl_803E143C;
extern f32 lbl_803E1440;
void dll_9E_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80318260;
  GfxCmd *e = buf.entries;
  GfxCmd *end;
  u32 fl;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &tab[0x1b0]; e[0].mode = 4;
  e[0].x = lbl_803E1418; e[0].y = lbl_803E1418; e[0].z = lbl_803E1418;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &tab[0x1b0]; e[1].mode = 2;
  e[1].x = lbl_803E141C; e[1].y = lbl_803E1420; e[1].z = lbl_803E141C;
  e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x400000;
  e[2].x = lbl_803E1418; e[2].y = lbl_803E1424; e[2].z = lbl_803E1418;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = &tab[0x1b0]; e[3].mode = 2;
  e[3].x = lbl_803E1428; e[3].y = lbl_803E1428; e[3].z = lbl_803E1428;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = &tab[0x174]; e[4].mode = 4;
  e[4].x = lbl_803E142C; e[4].y = lbl_803E1418; e[4].z = lbl_803E1418;
  e[5].layer = 1; e[5].flags = 0x15; e[5].tex = &tab[0x1b0]; e[5].mode = 0x4000;
  e[5].x = lbl_803E1430; e[5].y = lbl_803E1418; e[5].z = lbl_803E1418;
  e[6].layer = 1; e[6].flags = 0; e[6].tex = (void *)0; e[6].mode = 0x400000;
  e[6].x = lbl_803E1418; e[6].y = lbl_803E1418; e[6].z = lbl_803E1418;
  e[7].layer = 2; e[7].flags = 0x7a; e[7].tex = (void *)0; e[7].mode = 0x10000;
  e[7].x = lbl_803E1418; e[7].y = lbl_803E1418; e[7].z = lbl_803E1418;
  e[8].layer = 2; e[8].flags = 0x15; e[8].tex = &tab[0x1b0]; e[8].mode = 8;
  e[8].x = lbl_803E1434; e[8].y = lbl_803E1438; e[8].z = lbl_803E1418;
  e[9].layer = 2; e[9].flags = 0x15; e[9].tex = &tab[0x1b0]; e[9].mode = 0x4000;
  e[9].x = lbl_803E1430; e[9].y = lbl_803E1418; e[9].z = lbl_803E1418;
  e[10].layer = 2; e[10].flags = 0; e[10].tex = (void *)0; e[10].mode = 0x400000;
  e[10].x = lbl_803E1418; e[10].y = lbl_803E143C; e[10].z = lbl_803E1418;
  e[11].layer = 3; e[11].flags = 0x15; e[11].tex = &tab[0x1b0]; e[11].mode = 0x4000;
  e[11].x = lbl_803E1430; e[11].y = lbl_803E1418; e[11].z = lbl_803E1418;
  e[12].layer = 3; e[12].flags = 0; e[12].tex = (void *)0; e[12].mode = 0x400000;
  e[12].x = lbl_803E1418; e[12].y = lbl_803E143C; e[12].z = lbl_803E1418;
  e[13].layer = 3; e[13].flags = 7; e[13].tex = &tab[0x174]; e[13].mode = 4;
  e[13].x = lbl_803E1418; e[13].y = lbl_803E1418; e[13].z = lbl_803E1418;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E1418; buf.pos[1] = lbl_803E1418; buf.pos[2] = lbl_803E1418;
  buf.col[0] = lbl_803E1418; buf.col[1] = lbl_803E1418; buf.col[2] = lbl_803E1418;
  buf.scale = lbl_803E1440;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  end = e + 14;
  buf.count = end - e;
  buf.hw[0] = *(s16 *)&tab[0x1f8]; buf.hw[1] = *(s16 *)&tab[0x1fa];
  buf.hw[2] = *(s16 *)&tab[0x1fc]; buf.hw[3] = *(s16 *)&tab[0x1fe];
  buf.hw[4] = *(s16 *)&tab[0x200]; buf.hw[5] = *(s16 *)&tab[0x202];
  buf.hw[6] = *(s16 *)&tab[0x204];
  buf.cmds = e;
  fl = 0xc0100c0;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E1418 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1418 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1418 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1418 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1418 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1418 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[0xd4],0x46c,0);
}

/*
 * --INFO--
 *
 * Function: dll_9F_func03
 * EN v1.0 Address: 0x800FDE18
 * EN v1.0 Size: 1056b
 */
extern u8 lbl_80318488[];
extern f32 lbl_803E1448;
extern f32 lbl_803E144C;
extern f32 lbl_803E1450;
extern f32 lbl_803E1454;
extern f32 lbl_803E1458;
extern f32 lbl_803E145C;
extern f32 lbl_803E1460;
extern f32 lbl_803E1464;
extern f32 lbl_803E1468;
extern f32 lbl_803E146C;
extern f32 lbl_803E1470;
extern f32 lbl_803E1474;
extern f32 lbl_803E1478;
extern f32 lbl_803E147C;
void dll_9F_func03(short *param_1,int param_2,int param_3,uint param_4)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80318488;
  GfxCmd *base = buf.entries;
  GfxCmd *e = base;
  int head = *param_1;
  u32 fl;

  if (head != 0) {
    e->layer = 0; e->flags = 0x15; e->tex = &tab[0x1b0]; e->mode = 0x80;
    e->x = lbl_803E1448; e->y = lbl_803E1448;
    e->z = (f32)head;
    e = base + 1;
  }
  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &tab[0x1b0]; e[0].mode = 4;
  e[0].x = lbl_803E1448; e[0].y = lbl_803E1448; e[0].z = lbl_803E1448;
  e[1].layer = 0; e[1].flags = 7; e[1].tex = &tab[0x164]; e[1].mode = 2;
  e[1].x = lbl_803E144C; e[1].y = lbl_803E144C; e[1].z = lbl_803E1450;
  e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0x174]; e[2].mode = 2;
  e[2].x = lbl_803E1454; e[2].y = lbl_803E1454; e[2].z = lbl_803E1450;
  e[3].layer = 0; e[3].flags = 7; e[3].tex = &tab[0x184]; e[3].mode = 2;
  e[3].x = lbl_803E144C; e[3].y = lbl_803E144C; e[3].z = lbl_803E1450;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = &tab[0x174]; e[4].mode = 4;
  e[4].x = lbl_803E1458; e[4].y = lbl_803E1448; e[4].z = lbl_803E1448;
  e[5].layer = 1; e[5].flags = 0x15; e[5].tex = &tab[0x1b0]; e[5].mode = 0x4000;
  e[5].x = lbl_803E145C; e[5].y = lbl_803E1460; e[5].z = lbl_803E1448;
  e[6].layer = 1; e[6].flags = 0; e[6].tex = (void *)0; e[6].mode = 0x400000;
  e[6].x = lbl_803E1448; e[6].y = lbl_803E1448; e[6].z = lbl_803E1464;
  e[7].layer = 2; e[7].flags = 0x15; e[7].tex = &tab[0x1b0]; e[7].mode = 0x4000;
  e[7].x = lbl_803E145C; e[7].y = lbl_803E1460; e[7].z = lbl_803E1448;
  e[8].layer = 2; e[8].flags = 0; e[8].tex = (void *)0; e[8].mode = 0x400000;
  e[8].x = lbl_803E1448; e[8].y = lbl_803E1448; e[8].z = lbl_803E1468;
  e[9].layer = 2; e[9].flags = 0x15; e[9].tex = &tab[0x1b0]; e[9].mode = 8;
  e[9].x = lbl_803E146C; e[9].y = lbl_803E146C; e[9].z = lbl_803E1470;
  e[10].layer = 3; e[10].flags = 0x15; e[10].tex = &tab[0x1b0]; e[10].mode = 0x4000;
  e[10].x = lbl_803E145C; e[10].y = lbl_803E145C; e[10].z = lbl_803E1448;
  e[11].layer = 3; e[11].flags = 0; e[11].tex = (void *)0; e[11].mode = 0x400000;
  e[11].x = lbl_803E1448; e[11].y = lbl_803E1448; e[11].z = lbl_803E1474;
  e[12].layer = 3; e[12].flags = 0x15; e[12].tex = &tab[0x1b0]; e[12].mode = 8;
  e[12].x = lbl_803E146C; e[12].y = lbl_803E146C; e[12].z = lbl_803E146C;
  e[13].layer = 4; e[13].flags = 0x15; e[13].tex = &tab[0x1b0]; e[13].mode = 0x4000;
  e[13].x = lbl_803E145C; e[13].y = lbl_803E145C; e[13].z = lbl_803E1448;
  e[14].layer = 4; e[14].flags = 7; e[14].tex = &tab[0x174]; e[14].mode = 4;
  e[14].x = lbl_803E1448; e[14].y = lbl_803E1448; e[14].z = lbl_803E1448;
  e[15].layer = 4; e[15].flags = 0; e[15].tex = (void *)0; e[15].mode = 0x400000;
  e[15].x = lbl_803E1448; e[15].y = lbl_803E1448; e[15].z = lbl_803E1478;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E1448; buf.pos[1] = lbl_803E1448; buf.pos[2] = lbl_803E1448;
  buf.col[0] = lbl_803E1448; buf.col[1] = lbl_803E1448; buf.col[2] = lbl_803E1448;
  buf.scale = lbl_803E147C;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = &e[16] - base;
  buf.hw[0] = *(s16 *)&tab[0x1f8]; buf.hw[1] = *(s16 *)&tab[0x1fa];
  buf.hw[2] = *(s16 *)&tab[0x1fc]; buf.hw[3] = *(s16 *)&tab[0x1fe];
  buf.hw[4] = *(s16 *)&tab[0x200]; buf.hw[5] = *(s16 *)&tab[0x202];
  buf.hw[6] = *(s16 *)&tab[0x204];
  buf.cmds = buf.entries;
  fl = 0xc0104c0;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E1448 + *(f32 *)(param_1 + 0xc);
      buf.pos[1] = lbl_803E1448 + *(f32 *)(param_1 + 0xe);
      buf.pos[2] = lbl_803E1448 + *(f32 *)(param_1 + 0x10);
    } else {
      buf.pos[0] = lbl_803E1448 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1448 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1448 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[0xd4],0x46c,0);
}

/*
 * --INFO--
 *
 * Function: dll_A0_func03
 * EN v1.0 Address: 0x800FD820
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FE4DC
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803186B0[];
extern f32 lbl_803E1488;
extern f32 lbl_803E148C;
extern f32 lbl_803E1490;
extern f32 lbl_803E1494;
extern f32 lbl_803E1498;
extern f32 lbl_803E149C;
extern f32 lbl_803E14A0;
extern f32 lbl_803E14A4;
extern f32 lbl_803E14A8;
extern f32 lbl_803E14AC;
extern f32 lbl_803E14B0;
void dll_A0_func03(u8 *param_1,int param_2,int param_3,uint param_4)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_803186B0;
  GfxCmd *e = buf.entries;
  GfxCmd *p;
  u32 fl;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &tab[0x1b0]; e[0].mode = 4;
  e[0].x = lbl_803E1488; e[0].y = lbl_803E1488; e[0].z = lbl_803E1488;
  if (param_2 == 0) {
    e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &tab[0x1b0]; e[1].mode = 2;
    e[1].x = lbl_803E148C; e[1].y = lbl_803E1490; e[1].z = lbl_803E148C;
    p = e + 2;
  } else {
    e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &tab[0x1b0]; e[1].mode = 2;
    e[1].x = lbl_803E148C; e[1].y = lbl_803E1494; e[1].z = lbl_803E148C;
    p = e + 2;
  }
  p[0].layer = 1; p[0].flags = 0x15; p[0].tex = &tab[0x1b0]; p[0].mode = 2;
  p[0].x = lbl_803E1498; p[0].y = lbl_803E1498; p[0].z = lbl_803E1498;
  p[1].layer = 1; p[1].flags = 7; p[1].tex = &tab[0x174]; p[1].mode = 4;
  p[1].x = lbl_803E149C; p[1].y = lbl_803E1488; p[1].z = lbl_803E1488;
  p[2].layer = 1; p[2].flags = 0x15; p[2].tex = &tab[0x1b0]; p[2].mode = 0x4000;
  p[2].x = lbl_803E14A0; p[2].y = lbl_803E14A4; p[2].z = lbl_803E1488;
  p[3].layer = 2; p[3].flags = 7; p[3].tex = &tab[0x174]; p[3].mode = 2;
  p[3].x = lbl_803E14A8; p[3].y = lbl_803E14A4; p[3].z = lbl_803E14A8;
  p[4].layer = 2; p[4].flags = 7; p[4].tex = &tab[0x184]; p[4].mode = 2;
  p[4].x = lbl_803E14AC; p[4].y = lbl_803E14A4; p[4].z = lbl_803E14AC;
  p[5].layer = 2; p[5].flags = 0x15; p[5].tex = &tab[0x1b0]; p[5].mode = 0x4000;
  p[5].x = lbl_803E14A0; p[5].y = lbl_803E14A4; p[5].z = lbl_803E1488;
  p[6].layer = 3; p[6].flags = 7; p[6].tex = &tab[0x174]; p[6].mode = 4;
  p[6].x = lbl_803E1488; p[6].y = lbl_803E1488; p[6].z = lbl_803E1488;
  p[7].layer = 3; p[7].flags = 0x15; p[7].tex = &tab[0x1b0]; p[7].mode = 0x4000;
  p[7].x = lbl_803E14B0; p[7].y = lbl_803E14A4; p[7].z = lbl_803E1488;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E1488; buf.pos[1] = lbl_803E1488; buf.pos[2] = lbl_803E1488;
  buf.col[0] = lbl_803E1488; buf.col[1] = lbl_803E1488; buf.col[2] = lbl_803E1488;
  buf.scale = lbl_803E14A4;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = &p[8] - e;
  buf.hw[0] = *(s16 *)&tab[0x1f8]; buf.hw[1] = *(s16 *)&tab[0x1fa];
  buf.hw[2] = *(s16 *)&tab[0x1fc]; buf.hw[3] = *(s16 *)&tab[0x1fe];
  buf.hw[4] = *(s16 *)&tab[0x200]; buf.hw[5] = *(s16 *)&tab[0x202];
  buf.hw[6] = *(s16 *)&tab[0x204];
  buf.cmds = buf.entries;
  fl = 0xc010480;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E1488 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1488 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1488 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1488 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1488 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1488 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[0xd4],0x1d9,0);
}

/*
 * --INFO--
 *
 * Function: dll_A1_func03
 * EN v1.0 Address: 0x800FD884
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FE844
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803188D8[];
extern f32 lbl_803E14B8;
extern f32 lbl_803E14BC;
extern f32 lbl_803E14C0;
extern f32 lbl_803E14C4;
extern f32 lbl_803E14C8;
extern f32 lbl_803E14CC;
extern f32 lbl_803E14D0;
extern f32 lbl_803E14D4;
extern f32 lbl_803E14D8;
extern f32 lbl_803E14DC;
void dll_A1_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4)
{
  struct {
    GfxCmd *cmds;
    int ctx;
    u8 pad0[0x18];
    f32 col[3];
    f32 pos[3];
    f32 scale;
    u32 v3c;
    u32 v40;
    s16 v44;
    s16 hw[7];
    u32 flags;
    u8 v58, v59, v5a, v5b, v5c, count;
    u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_803188D8;
  GfxCmd *e = buf.entries;
  GfxCmd *end;
  u32 fl;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &tab[0x1b0]; e[0].mode = 4;
  e[0].x = lbl_803E14B8; e[0].y = lbl_803E14B8; e[0].z = lbl_803E14B8;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &tab[0x1b0]; e[1].mode = 2;
  e[1].x = lbl_803E14BC; e[1].y = lbl_803E14BC; e[1].z = lbl_803E14C0;
  e[2].layer = 1; e[2].flags = 0x15; e[2].tex = &tab[0x1b0]; e[2].mode = 4;
  e[2].x = lbl_803E14C4; e[2].y = lbl_803E14B8; e[2].z = lbl_803E14B8;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = &tab[0x1b0]; e[3].mode = 0x4000;
  e[3].x = lbl_803E14C8; e[3].y = lbl_803E14CC; e[3].z = lbl_803E14B8;
  e[4].layer = 1; e[4].flags = 0x15; e[4].tex = &tab[0x1b0]; e[4].mode = 2;
  e[4].x = lbl_803E14D0; e[4].y = lbl_803E14D0; e[4].z = lbl_803E14D4;
  e[5].layer = 2; e[5].flags = 0x15; e[5].tex = &tab[0x1b0]; e[5].mode = 0x4000;
  e[5].x = lbl_803E14C8; e[5].y = lbl_803E14CC; e[5].z = lbl_803E14B8;
  e[6].layer = 3; e[6].flags = 1; e[6].tex = (void *)0; e[6].mode = 0x2000;
  e[6].x = lbl_803E14B8; e[6].y = lbl_803E14B8; e[6].z = lbl_803E14B8;
  e[7].layer = 4; e[7].flags = 0x15; e[7].tex = &tab[0x1b0]; e[7].mode = 2;
  e[7].x = lbl_803E14D8; e[7].y = lbl_803E14D8; e[7].z = lbl_803E14C8;
  e[8].layer = 4; e[8].flags = 0x15; e[8].tex = &tab[0x1b0]; e[8].mode = 0x4000;
  e[8].x = lbl_803E14C8; e[8].y = lbl_803E14CC; e[8].z = lbl_803E14B8;
  e[9].layer = 4; e[9].flags = 0x6dd; e[9].tex = (void *)0; e[9].mode = 0x800000;
  e[9].x = lbl_803E14C8; e[9].y = lbl_803E14B8; e[9].z = lbl_803E14B8;
  e[10].layer = 5; e[10].flags = 0x15; e[10].tex = &tab[0x1b0]; e[10].mode = 0x4000;
  e[10].x = lbl_803E14C8; e[10].y = lbl_803E14CC; e[10].z = lbl_803E14B8;
  e[11].layer = 5; e[11].flags = 0x6de; e[11].tex = (void *)0; e[11].mode = 0x800000;
  e[11].x = lbl_803E14D0; e[11].y = lbl_803E14B8; e[11].z = lbl_803E14B8;
  e[12].layer = 5; e[12].flags = 0x6dd; e[12].tex = (void *)0; e[12].mode = 0x800000;
  e[12].x = lbl_803E14C8; e[12].y = lbl_803E14B8; e[12].z = lbl_803E14B8;
  e[13].layer = 6; e[13].flags = 4; e[13].tex = (void *)0; e[13].mode = 0x2000;
  e[13].x = lbl_803E14B8; e[13].y = lbl_803E14B8; e[13].z = lbl_803E14B8;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E14B8; buf.pos[1] = lbl_803E14B8; buf.pos[2] = lbl_803E14B8;
  buf.col[0] = lbl_803E14B8; buf.col[1] = lbl_803E14B8; buf.col[2] = lbl_803E14B8;
  buf.scale = lbl_803E14DC;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  end = e + 14;
  buf.count = end - e;
  buf.hw[0] = *(s16 *)&tab[0x1f8]; buf.hw[1] = *(s16 *)&tab[0x1fa];
  buf.hw[2] = *(s16 *)&tab[0x1fc]; buf.hw[3] = *(s16 *)&tab[0x1fe];
  buf.hw[4] = *(s16 *)&tab[0x200]; buf.hw[5] = *(s16 *)&tab[0x202];
  buf.hw[6] = *(s16 *)&tab[0x204];
  buf.cmds = e;
  fl = 0xc0104c0;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E14B8 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E14B8 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E14B8 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E14B8 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E14B8 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E14B8 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[0xd4],0x203,0);
}

/*
 * --INFO--
 *
 * Function: dll_A2_func03
 * EN v1.0 Address: 0x800FD8F0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FEBC4
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80318B00[];
extern f32 lbl_803E14E0;
extern f32 lbl_803E14E4;
extern f32 lbl_803E14E8;
extern f32 lbl_803E14EC;
extern f32 lbl_803E14F0;
extern f32 lbl_803E14F4;
extern f32 lbl_803E14F8;
extern f32 lbl_803E14FC;
extern f32 lbl_803E1500;
void dll_A2_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4)
{
  struct {
    GfxCmd *cmds;
    int ctx;
    u8 pad0[0x18];
    f32 col[3];
    f32 pos[3];
    f32 scale;
    u32 v3c;
    u32 v40;
    s16 v44;
    s16 hw[7];
    u32 flags;
    u8 v58, v59, v5a, v5b, v5c, count;
    u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80318B00;
  GfxCmd *e = buf.entries;
  GfxCmd *end;
  u32 fl;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &tab[0x1b0]; e[0].mode = 4;
  e[0].x = lbl_803E14E0; e[0].y = lbl_803E14E0; e[0].z = lbl_803E14E0;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &tab[0x1b0]; e[1].mode = 2;
  e[1].x = lbl_803E14E4; e[1].y = lbl_803E14E4; e[1].z = lbl_803E14E8;
  e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0x164]; e[2].mode = 8;
  e[2].x = lbl_803E14EC; e[2].y = lbl_803E14E0; e[2].z = lbl_803E14E0;
  e[3].layer = 1; e[3].flags = 7; e[3].tex = &tab[0x174]; e[3].mode = 2;
  e[3].x = lbl_803E14F0; e[3].y = lbl_803E14F0; e[3].z = lbl_803E14F4;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = &tab[0x184]; e[4].mode = 2;
  e[4].x = lbl_803E14F4; e[4].y = lbl_803E14F4; e[4].z = lbl_803E14F8;
  e[5].layer = 1; e[5].flags = 7; e[5].tex = &tab[0x174]; e[5].mode = 4;
  e[5].x = lbl_803E14EC; e[5].y = lbl_803E14E0; e[5].z = lbl_803E14E0;
  e[6].layer = 1; e[6].flags = 0x15; e[6].tex = &tab[0x1b0]; e[6].mode = 0x4000;
  e[6].x = lbl_803E14FC; e[6].y = lbl_803E1500; e[6].z = lbl_803E14E0;
  e[7].layer = 2; e[7].flags = 7; e[7].tex = &tab[0x174]; e[7].mode = 2;
  e[7].x = lbl_803E14FC; e[7].y = lbl_803E14FC; e[7].z = lbl_803E14FC;
  e[8].layer = 2; e[8].flags = 7; e[8].tex = &tab[0x184]; e[8].mode = 2;
  e[8].x = lbl_803E14FC; e[8].y = lbl_803E14FC; e[8].z = lbl_803E14FC;
  e[9].layer = 2; e[9].flags = 0x15; e[9].tex = &tab[0x1b0]; e[9].mode = 0x4000;
  e[9].x = lbl_803E14FC; e[9].y = lbl_803E1500; e[9].z = lbl_803E14E0;
  e[10].layer = 3; e[10].flags = 7; e[10].tex = &tab[0x174]; e[10].mode = 4;
  e[10].x = lbl_803E14E0; e[10].y = lbl_803E14E0; e[10].z = lbl_803E14E0;
  e[11].layer = 3; e[11].flags = 0x15; e[11].tex = &tab[0x1b0]; e[11].mode = 0x4000;
  e[11].x = lbl_803E14FC; e[11].y = lbl_803E1500; e[11].z = lbl_803E14E0;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E14E0; buf.pos[1] = lbl_803E14E0; buf.pos[2] = lbl_803E14E0;
  buf.col[0] = lbl_803E14E0; buf.col[1] = lbl_803E14E0; buf.col[2] = lbl_803E14E0;
  buf.scale = lbl_803E14FC;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  end = e + 12;
  buf.count = end - e;
  buf.hw[0] = *(s16 *)&tab[0x1f8]; buf.hw[1] = *(s16 *)&tab[0x1fa];
  buf.hw[2] = *(s16 *)&tab[0x1fc]; buf.hw[3] = *(s16 *)&tab[0x1fe];
  buf.hw[4] = *(s16 *)&tab[0x200]; buf.hw[5] = *(s16 *)&tab[0x202];
  buf.hw[6] = *(s16 *)&tab[0x204];
  buf.cmds = e;
  fl = 0xc010480;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E14E0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E14E0 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E14E0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E14E0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E14E0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E14E0 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,tab,0x18,&tab[0xd4],0x24,0);
}

/*
 * --INFO--
 *
 * Function: dll_A5_func03
 * EN v1.0 Address: 0x800FD954
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FEF20
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80318D48[];
extern f32 lbl_803E1508;
extern f32 lbl_803E150C;
extern f32 lbl_803E1510;
extern f32 lbl_803E1514;
extern f32 lbl_803E1518;
extern f32 lbl_803E151C;
extern f32 lbl_803E1520;
extern f32 lbl_803E1524;
void dll_A5_func03(int param_1, int param_2, int param_3, uint param_4)
{
  struct { GfxCmd *cmds; int ctx; u8 pad0[0x18]; f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c, count; u8 pad1[2]; GfxCmd entries[32]; } buf;
  GfxCmd *e = buf.entries;
  int ctx;
  e[0].layer = 0; e[0].flags = 8; e[0].tex = &lbl_80318D48[104]; e[0].mode = 4;
  e[0].x = lbl_803E1508; e[0].y = lbl_803E1508; e[0].z = lbl_803E1508;
  e[1].layer = 0; e[1].flags = 4; e[1].tex = (void *)0; e[1].mode = 2;
  e[1].x = lbl_803E150C; e[1].y = lbl_803E150C; e[1].z = lbl_803E1510;
  e[2].layer = 0; e[2].flags = 4; e[2].tex = (void *)0; e[2].mode = 2;
  e[2].x = lbl_803E1514; e[2].y = lbl_803E1514; e[2].z = lbl_803E1510;
  e[3].layer = 0; e[3].flags = 0; e[3].tex = (void *)0; e[3].mode = 0x80;
  e[3].x = lbl_803E1508; e[3].y = lbl_803E1508; e[3].z = lbl_803E1514;
  e[4].layer = 0; e[4].flags = 0x7a; e[4].tex = (void *)0; e[4].mode = 0x10000;
  e[4].x = lbl_803E1508; e[4].y = lbl_803E1508; e[4].z = lbl_803E1508;
  e[5].layer = 1; e[5].flags = 8; e[5].tex = &lbl_80318D48[104]; e[5].mode = 4;
  e[5].x = lbl_803E1518; e[5].y = lbl_803E1508; e[5].z = lbl_803E1508;
  e[6].layer = 1; e[6].flags = 0; e[6].tex = (void *)0; e[6].mode = 0x400000;
  e[6].x = lbl_803E1508; e[6].y = lbl_803E1508; e[6].z = lbl_803E150C;
  e[7].layer = 1; e[7].flags = 8; e[7].tex = &lbl_80318D48[104]; e[7].mode = 2;
  e[7].x = lbl_803E150C; e[7].y = lbl_803E150C; e[7].z = lbl_803E151C;
  e[8].layer = 1; e[8].flags = 0x3a1; e[8].tex = (void *)0; e[8].mode = 0x1800000;
  e[8].x = lbl_803E150C; e[8].y = lbl_803E1508; e[8].z = lbl_803E1520;
  e[9].layer = 2; e[9].flags = 0x7a; e[9].tex = (void *)0; e[9].mode = 0x10000;
  e[9].x = lbl_803E1508; e[9].y = lbl_803E1508; e[9].z = lbl_803E1508;
  e[10].layer = 2; e[10].flags = 8; e[10].tex = &lbl_80318D48[104]; e[10].mode = 4;
  e[10].x = lbl_803E1508; e[10].y = lbl_803E1508; e[10].z = lbl_803E1508;
  e[11].layer = 2; e[11].flags = 0; e[11].tex = (void *)0; e[11].mode = 0x400000;
  e[11].x = lbl_803E1508; e[11].y = lbl_803E1508; e[11].z = lbl_803E1524;
  e[12].layer = 2; e[12].flags = 0x3a0; e[12].tex = (void *)0; e[12].mode = 0x800000;
  e[12].x = lbl_803E150C; e[12].y = lbl_803E1508; e[12].z = lbl_803E1508;
  buf.v58 = 0x800000;
  ctx = param_1;
  buf.ctx = ctx;
  buf.v44 = 0x800000;
  buf.pos[0] = lbl_803E1524; buf.pos[1] = lbl_803E1524; buf.pos[2] = lbl_803E1524;
  buf.col[0] = lbl_803E1508; buf.col[1] = lbl_803E1508; buf.col[2] = lbl_803E1508;
  buf.scale = lbl_803E150C;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 8;
  buf.v5a = 0;
  buf.v5b = 0x3c;
  buf.count = 13;
  buf.hw[0] = *(s16 *)&lbl_80318D48[120]; buf.hw[1] = *(s16 *)&lbl_80318D48[122]; buf.hw[2] = *(s16 *)&lbl_80318D48[124]; buf.hw[3] = *(s16 *)&lbl_80318D48[126];
  buf.hw[4] = *(s16 *)&lbl_80318D48[128]; buf.hw[5] = *(s16 *)&lbl_80318D48[130]; buf.hw[6] = *(s16 *)&lbl_80318D48[132];
  buf.cmds = buf.entries;
  buf.flags = 0x4040000 | *(s16 *)&lbl_80318D48[132];
  if ((param_4 & 1) != 0) {
    if (ctx == 0) {
      buf.pos[0] = lbl_803E1524 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1524 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1524 + *(f32 *)(param_3 + 0x14);
    } else {
      buf.pos[0] = lbl_803E1524 + *(f32 *)(ctx + 0x18);
      buf.pos[1] = lbl_803E1524 + *(f32 *)(ctx + 0x1c);
      buf.pos[2] = lbl_803E1524 + *(f32 *)(ctx + 0x20);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf, 0, 8, &lbl_80318D48[0], 4, &lbl_80318D48[80], 0x5e0, 0);
}

extern u8 lbl_80318E40[];
extern f32 lbl_803E1570;
extern f32 lbl_803E1574;
extern f32 lbl_803E1578;
extern f32 lbl_803E157C;
extern f32 lbl_803E1580;
extern f32 lbl_803E1584;
extern f32 lbl_803E1588;
void dll_A7_func03(short *param_1, int param_2, u8 *param_3, uint param_4, undefined4 param_5,
                 uint *param_6)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80318E40;
  GfxCmd *e = buf.entries;
  GfxCmd *p;
  uint v0, v1, v2;
  int v3;
  u32 fl;

  v1 = 0x30;
  v2 = 0x31;
  v0 = 1;
  v3 = 0x50;
  if (param_6 != 0) {
    v0 = param_6[0];
    v1 = param_6[1];
    v2 = param_6[2];
    v3 = param_6[3];
  }
  e[0].layer = 0; e[0].flags = 8; e[0].tex = &tab[0x68]; e[0].mode = 4;
  e[0].x = lbl_803E1570; e[0].y = lbl_803E1570; e[0].z = lbl_803E1570;
  e[1].layer = 0; e[1].flags = 8; e[1].tex = &tab[0x68]; e[1].mode = 2;
  if (param_1 != 0) {
    e[1].x = lbl_803E1574 * *(f32 *)(param_1 + 4);
    e[1].y = lbl_803E1578 * *(f32 *)(param_1 + 4);
    e[1].z = lbl_803E1574 * *(f32 *)(param_1 + 4);
  } else {
    e[1].x = lbl_803E1574; e[1].y = lbl_803E1578; e[1].z = lbl_803E1574;
  }
  e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x80;
  e[2].x = lbl_803E1570; e[2].y = lbl_803E1570;
  if (param_1 != 0) {
    e[2].z = (f32)*param_1;
  } else {
    e[2].z = lbl_803E1570;
  }
  e[3].layer = 1; e[3].flags = 8; e[3].tex = &tab[0x68]; e[3].mode = 4;
  e[3].x = lbl_803E157C; e[3].y = lbl_803E1570; e[3].z = lbl_803E1570;
  e[4].layer = 1; e[4].flags = v3; e[4].tex = (void *)0; e[4].mode = 0x20000000;
  e[4].x = (f32)(int)v0; e[4].y = (f32)(int)v1; e[4].z = (f32)(int)v2;
  p = e + 5;
  if (param_2 != 1) {
    p->layer = 2; p->flags = 0x3b; p->tex = (void *)0; p->mode = 0x1800000;
    p->x = lbl_803E1580; p->y = lbl_803E1570; p->z = lbl_803E1584;
    p++;
  }
  p[0].layer = 2; p[0].flags = 0; p[0].tex = (void *)0; p[0].mode = 0x100;
  p[0].x = lbl_803E1570; p[0].y = lbl_803E1570; p[0].z = lbl_803E1588;
  p[1].layer = 3; p[1].flags = 1; p[1].tex = (void *)0; p[1].mode = 0x2000;
  p[1].x = lbl_803E1570; p[1].y = lbl_803E1570; p[1].z = lbl_803E1570;
  p[2].layer = 4; p[2].flags = 8; p[2].tex = &tab[0x68]; p[2].mode = 4;
  p[2].x = lbl_803E1570; p[2].y = lbl_803E1570; p[2].z = lbl_803E1570;
  p[3].layer = 4; p[3].flags = 0; p[3].tex = (void *)0; p[3].mode = 0x20000000;
  p[3].x = (f32)(int)v0; p[3].y = (f32)(int)v1; p[3].z = (f32)(int)v2;

  buf.v58 = param_2;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E1570;
  if (param_3 != 0) {
    buf.pos[1] = *(f32 *)(param_3 + 0x10);
  } else {
    buf.pos[1] = lbl_803E1570;
  }
  buf.pos[2] = lbl_803E1570;
  buf.col[0] = lbl_803E1570; buf.col[1] = lbl_803E1570; buf.col[2] = lbl_803E1570;
  buf.scale = lbl_803E1580;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 8;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = &p[4] - e;
  buf.hw[0] = *(s16 *)&tab[0x78]; buf.hw[1] = *(s16 *)&tab[0x7a];
  buf.hw[2] = *(s16 *)&tab[0x7c]; buf.hw[3] = *(s16 *)&tab[0x7e];
  buf.hw[4] = *(s16 *)&tab[0x80]; buf.hw[5] = *(s16 *)&tab[0x82];
  buf.hw[6] = *(s16 *)&tab[0x84];
  buf.cmds = buf.entries;
  fl = 0x4040000;
  buf.flags = fl;
  fl |= (param_4 | 0x80);
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = buf.pos[0] + *(f32 *)(param_1 + 0xc);
      buf.pos[1] = buf.pos[1] + *(f32 *)(param_1 + 0xe);
      buf.pos[2] = lbl_803E1570 + *(f32 *)(param_1 + 0x10);
    } else {
      buf.pos[0] = buf.pos[0] + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = buf.pos[1] + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1570 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf, 0, 8, tab, 4, &tab[0x50], 0x5e0, 0);
}

/*
 * --INFO--
 *
 * Function: dll_A6_func03
 * EN v1.0 Address: 0x800FF004
 * EN v1.0 Size: 1684b
 */
extern u32 randomGetRange(int min, int max);
extern u8 lbl_80318DF0[];
extern u8 lbl_80318E10[];
extern u8 lbl_803DB980;
extern u8 lbl_803DB988;
extern f32 lbl_803E1530;
extern f32 lbl_803E1534;
extern f32 lbl_803E1538;
extern f32 lbl_803E153C;
extern f32 lbl_803E1540;
extern f32 lbl_803E1544;
extern f32 lbl_803E1548;
extern f32 lbl_803E154C;
extern f32 lbl_803E1550;
extern f32 lbl_803E1554;
extern f32 lbl_803E1558;
extern f32 lbl_803E155C;
extern f32 lbl_803E1560;
extern f32 lbl_803E1564;
void dll_A6_func03(short *param_1,int param_2,u8 *param_3,uint param_4)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  GfxCmd *e = buf.entries;
  GfxCmd *p = e;
  f32 zr;
  f32 yr;
  u32 fl;

  if (param_2 == 0) {
    p->layer = 0; p->flags = 3; p->tex = &lbl_803DB988; p->mode = 8;
    p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
    p->y = (f32)(int)(randomGetRange(0, 0x14) + 0x87);
    p->z = (f32)(int)(randomGetRange(0, 0x14) + 0x41);
    p++;
  } else if (param_2 == 1) {
    p->layer = 0; p->flags = 3; p->tex = &lbl_803DB988; p->mode = 8;
    p->y = p->x = (f32)(int)(randomGetRange(0, 0x5a) + 0x87);
    p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
    p++;
  }
  zr = (f32)(int)randomGetRange(0, 0xfffe);
  yr = (f32)(int)randomGetRange(-3000, -12000);
  p[0].layer = 0; p[0].flags = 0; p[0].tex = (void *)0; p[0].mode = 0x80;
  p[0].x = lbl_803E1530; p[0].y = yr; p[0].z = zr;
  p[1].layer = 0; p[1].flags = 3; p[1].tex = &lbl_803DB988; p[1].mode = 4;
  p[1].x = lbl_803E1530; p[1].y = lbl_803E1530; p[1].z = lbl_803E1530;
  p[2].layer = 0; p[2].flags = 3; p[2].tex = &lbl_803DB988; p[2].mode = 2;
  p[2].x = lbl_803E1534;
  p[2].y = lbl_803E153C * (f32)(int)randomGetRange(0, 0x19) + lbl_803E1538;
  p[2].z = lbl_803E153C * (f32)(int)randomGetRange(0, 10) + lbl_803E1540;
  p[3].layer = 1; p[3].flags = 3; p[3].tex = &lbl_803DB988; p[3].mode = 4;
  if (randomGetRange(0, 10) == 0) {
    p[3].x = lbl_803E1544 + (f32)(int)randomGetRange(0, 0x1e);
  } else {
    p[3].x = lbl_803E1548 + (f32)(int)randomGetRange(0, 10);
  }
  p[3].y = lbl_803E1530; p[3].z = lbl_803E1530;
  p[4].layer = 1; p[4].flags = 0; p[4].tex = (void *)0; p[4].mode = 0x80;
  p[4].x = lbl_803E1530; p[4].y = lbl_803E1530;
  p[4].z = (f32)(int)randomGetRange(0, 0xfffe);
  p[5].layer = 1; p[5].flags = 3; p[5].tex = &lbl_803DB988; p[5].mode = 2;
  p[5].x = lbl_803E154C; p[5].y = lbl_803E1550; p[5].z = lbl_803E1554;
  p[6].layer = 2; p[6].flags = 0; p[6].tex = (void *)0; p[6].mode = 0x80;
  p[6].x = lbl_803E1530; p[6].y = lbl_803E1530;
  p[6].z = (f32)(int)randomGetRange(0, 0xfffe);
  p[7].layer = 2; p[7].flags = 3; p[7].tex = &lbl_803DB988; p[7].mode = 4;
  p[7].x = lbl_803E1530; p[7].y = lbl_803E1530; p[7].z = lbl_803E1530;
  p[8].layer = 2; p[8].flags = 3; p[8].tex = &lbl_803DB988; p[8].mode = 2;
  p[8].x = lbl_803E1558; p[8].y = lbl_803E155C; p[8].z = lbl_803E1560;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E1530; buf.pos[1] = lbl_803E1530; buf.pos[2] = lbl_803E1530;
  buf.col[0] = lbl_803E1530; buf.col[1] = lbl_803E1530; buf.col[2] = lbl_803E1530;
  buf.scale = lbl_803E1564;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 3;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = &p[9] - e;
  buf.hw[0] = *(s16 *)&lbl_80318E10[0]; buf.hw[1] = *(s16 *)&lbl_80318E10[2];
  buf.hw[2] = *(s16 *)&lbl_80318E10[4]; buf.hw[3] = *(s16 *)&lbl_80318E10[6];
  buf.hw[4] = *(s16 *)&lbl_80318E10[8]; buf.hw[5] = *(s16 *)&lbl_80318E10[10];
  buf.hw[6] = *(s16 *)&lbl_80318E10[12];
  buf.cmds = buf.entries;
  fl = 0x4000400;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0 && param_3 != 0) {
      buf.pos[0] = lbl_803E1530 + (*(f32 *)(param_1 + 0xc) + *(f32 *)(param_3 + 0xc));
      buf.pos[1] = lbl_803E1530 + (*(f32 *)(param_1 + 0xe) + *(f32 *)(param_3 + 0x10));
      buf.pos[2] = lbl_803E1530 + (*(f32 *)(param_1 + 0x10) + *(f32 *)(param_3 + 0x14));
    } else if (param_1 != 0) {
      buf.pos[0] = buf.pos[0] + *(f32 *)(param_1 + 0xc);
      buf.pos[1] = buf.pos[1] + *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] = buf.pos[2] + *(f32 *)(buf.ctx + 0x20);
    } else if (param_3 != 0) {
      buf.pos[0] = buf.pos[0] + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = buf.pos[1] + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = buf.pos[2] + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,3,lbl_80318DF0,1,&lbl_803DB980,0x26a,0);
}
/*
 * --INFO--
 *
 * Function: FUN_800fd9c4
 * EN v1.0 Address: 0x800FD9C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800FF93C
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fd9c4(short *param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 uint *param_6)
{
}

/*
 * --INFO--
 *
 * Function: dll_A8_func03
 * EN v1.0 Address: 0x800FFB44
 * EN v1.0 Size: 952b
 */
extern u8 lbl_80318EE8[];
extern f32 lbl_803E1598;
extern f32 lbl_803E159C;
extern f32 lbl_803E15A0;
extern f32 lbl_803E15A4;
extern f32 lbl_803E15A8;
extern f32 lbl_803E15AC;
extern f32 lbl_803E15B0;
extern f32 lbl_803E15B4;
extern f32 lbl_803E15B8;
extern f32 lbl_803E15BC;
extern f32 lbl_803E15C0;
extern f32 lbl_803E15C4;
extern f32 lbl_803E15C8;
void dll_A8_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4,undefined4 param_5,
                 u8 *param_6)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80318EE8;
  f32 sx;
  GfxCmd *e;
  GfxCmd *p;
  u32 fl;

  if (param_6 != 0) {
    sx = lbl_803E1598;
  } else {
    sx = lbl_803E159C;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0xe; e[0].tex = &tab[0xf4]; e[0].mode = 4;
  e[0].x = lbl_803E15A0; e[0].y = lbl_803E15A0; e[0].z = lbl_803E15A0;
  if (param_6 != 0) {
    e[1].layer = 0; e[1].flags = 7; e[1].tex = &tab[0xd4]; e[1].mode = 2;
    e[1].x = lbl_803E15A4; e[1].y = lbl_803E15A8; e[1].z = lbl_803E15A4;
    e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0xe4]; e[2].mode = 2;
    e[2].x = lbl_803E15AC; e[2].y = lbl_803E15A8; e[2].z = lbl_803E15AC;
    p = e + 3;
  } else {
    e[1].layer = 0; e[1].flags = 7; e[1].tex = &tab[0xd4]; e[1].mode = 2;
    e[1].x = lbl_803E15A4; e[1].y = lbl_803E15B0; e[1].z = lbl_803E15A4;
    e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0xe4]; e[2].mode = 2;
    e[2].x = lbl_803E15B4; e[2].y = lbl_803E15B0; e[2].z = lbl_803E15B4;
    p = e + 3;
  }
  p[0].layer = 1; p[0].flags = 0xe; p[0].tex = &tab[0xf4]; p[0].mode = 2;
  p[0].x = lbl_803E15B8; p[0].y = lbl_803E15BC; p[0].z = lbl_803E15B8;
  p[1].layer = 1; p[1].flags = 0xe; p[1].tex = &tab[0xf4]; p[1].mode = 4;
  p[1].x = lbl_803E15C0; p[1].y = lbl_803E15A0; p[1].z = lbl_803E15A0;
  p[2].layer = 1; p[2].flags = 0xe; p[2].tex = &tab[0xf4]; p[2].mode = 0x4000;
  p[2].x = sx; p[2].y = lbl_803E15A0; p[2].z = lbl_803E15A0;
  p[3].layer = 2; p[3].flags = 0xe; p[3].tex = &tab[0xf4]; p[3].mode = 0x4000;
  p[3].x = sx; p[3].y = lbl_803E15A0; p[3].z = lbl_803E15A0;
  p[4].layer = 3; p[4].flags = 1; p[4].tex = (void *)0; p[4].mode = 0x2000;
  p[4].x = lbl_803E15A0; p[4].y = lbl_803E15A0; p[4].z = lbl_803E15A0;
  p[5].layer = 4; p[5].flags = 0xe; p[5].tex = &tab[0xf4]; p[5].mode = 4;
  p[5].x = lbl_803E15A0; p[5].y = lbl_803E15A0; p[5].z = lbl_803E15A0;
  p[6].layer = 4; p[6].flags = 0xe; p[6].tex = &tab[0xf4]; p[6].mode = 0x4000;
  p[6].x = sx; p[6].y = lbl_803E15A0; p[6].z = lbl_803E15A0;
  p[7].layer = 4; p[7].flags = 0xe; p[7].tex = &tab[0xf4]; p[7].mode = 2;
  p[7].x = lbl_803E15B8; p[7].y = lbl_803E15C4; p[7].z = lbl_803E15B8;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E15A0; buf.pos[1] = lbl_803E15C8; buf.pos[2] = lbl_803E15A0;
  buf.col[0] = lbl_803E15A0; buf.col[1] = lbl_803E15A0; buf.col[2] = lbl_803E15A0;
  buf.scale = lbl_803E15B8;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = &p[8] - e;
  buf.hw[0] = *(s16 *)&tab[0x110]; buf.hw[1] = *(s16 *)&tab[0x112];
  buf.hw[2] = *(s16 *)&tab[0x114]; buf.hw[3] = *(s16 *)&tab[0x116];
  buf.hw[4] = *(s16 *)&tab[0x118]; buf.hw[5] = *(s16 *)&tab[0x11a];
  buf.hw[6] = *(s16 *)&tab[0x11c];
  buf.cmds = buf.entries;
  fl = 0xc010040;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E15A0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E15C8 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E15A0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E15A0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E15C8 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E15A0 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0xe,tab,0xc,&tab[0x8c],0x586,0);
}

/*
 * --INFO--
 *
 * Function: dll_A9_func03
 * EN v1.0 Address: 0x800FFF04
 * EN v1.0 Size: 948b
 */
extern u8 lbl_80319028[];
extern f32 lbl_803E15D0;
extern f32 lbl_803E15D4;
extern f32 lbl_803E15D8;
extern f32 lbl_803E15DC;
extern f32 lbl_803E15E0;
extern f32 lbl_803E15E4;
extern f32 lbl_803E15E8;
extern f32 lbl_803E15EC;
extern f32 lbl_803E15F0;
extern f32 lbl_803E15F4;
extern f32 lbl_803E15F8;
extern f32 lbl_803E15FC;
void dll_A9_func03(u8 *param_1,int param_2,u8 *param_3,uint param_4,undefined4 param_5,
                 u8 *param_6)
{
  struct {
    GfxCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c; s8 count; u8 pad1[2];
    GfxCmd entries[32];
  } buf;
  u8 *tab = lbl_80319028;
  f32 sx;
  GfxCmd *e;
  GfxCmd *p;
  u32 fl;

  if (param_6 != 0) {
    sx = lbl_803E15D0;
  } else {
    sx = lbl_803E15D4;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0xe; e[0].tex = &tab[0xf4]; e[0].mode = 4;
  e[0].x = lbl_803E15D8; e[0].y = lbl_803E15D8; e[0].z = lbl_803E15D8;
  if (param_6 != 0) {
    e[1].layer = 0; e[1].flags = 7; e[1].tex = &tab[0xd4]; e[1].mode = 2;
    e[1].x = lbl_803E15DC; e[1].y = lbl_803E15E0; e[1].z = lbl_803E15DC;
    e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0xe4]; e[2].mode = 2;
    e[2].x = lbl_803E15E4; e[2].y = lbl_803E15E0; e[2].z = lbl_803E15E4;
    p = e + 3;
  } else {
    e[1].layer = 0; e[1].flags = 7; e[1].tex = &tab[0xd4]; e[1].mode = 2;
    e[1].x = lbl_803E15DC; e[1].y = lbl_803E15E8; e[1].z = lbl_803E15DC;
    e[2].layer = 0; e[2].flags = 7; e[2].tex = &tab[0xe4]; e[2].mode = 2;
    e[2].x = lbl_803E15EC; e[2].y = lbl_803E15E8; e[2].z = lbl_803E15EC;
    p = e + 3;
  }
  p[0].layer = 1; p[0].flags = 0xe; p[0].tex = &tab[0xf4]; p[0].mode = 2;
  p[0].x = lbl_803E15F0; p[0].y = lbl_803E15F4; p[0].z = lbl_803E15F0;
  p[1].layer = 1; p[1].flags = 0xe; p[1].tex = &tab[0xf4]; p[1].mode = 4;
  p[1].x = lbl_803E15F8; p[1].y = lbl_803E15D8; p[1].z = lbl_803E15D8;
  p[2].layer = 1; p[2].flags = 0xe; p[2].tex = &tab[0xf4]; p[2].mode = 0x4000;
  p[2].x = sx; p[2].y = lbl_803E15D8; p[2].z = lbl_803E15D8;
  p[3].layer = 2; p[3].flags = 0xe; p[3].tex = &tab[0xf4]; p[3].mode = 0x4000;
  p[3].x = sx; p[3].y = lbl_803E15D8; p[3].z = lbl_803E15D8;
  p[4].layer = 3; p[4].flags = 1; p[4].tex = (void *)0; p[4].mode = 0x2000;
  p[4].x = lbl_803E15D8; p[4].y = lbl_803E15D8; p[4].z = lbl_803E15D8;
  p[5].layer = 4; p[5].flags = 0xe; p[5].tex = &tab[0xf4]; p[5].mode = 4;
  p[5].x = lbl_803E15D8; p[5].y = lbl_803E15D8; p[5].z = lbl_803E15D8;
  p[6].layer = 4; p[6].flags = 0xe; p[6].tex = &tab[0xf4]; p[6].mode = 0x4000;
  p[6].x = sx; p[6].y = lbl_803E15D8; p[6].z = lbl_803E15D8;
  p[7].layer = 4; p[7].flags = 0xe; p[7].tex = &tab[0xf4]; p[7].mode = 2;
  p[7].x = lbl_803E15F0; p[7].y = lbl_803E15FC; p[7].z = lbl_803E15F0;

  buf.v58 = 0;
  buf.ctx = (int)param_1;
  buf.v44 = param_2;
  buf.pos[0] = lbl_803E15D8; buf.pos[1] = lbl_803E15D8; buf.pos[2] = lbl_803E15D8;
  buf.col[0] = lbl_803E15D8; buf.col[1] = lbl_803E15D8; buf.col[2] = lbl_803E15D8;
  buf.scale = lbl_803E15F0;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = &p[8] - e;
  buf.hw[0] = *(s16 *)&tab[0x110]; buf.hw[1] = *(s16 *)&tab[0x112];
  buf.hw[2] = *(s16 *)&tab[0x114]; buf.hw[3] = *(s16 *)&tab[0x116];
  buf.hw[4] = *(s16 *)&tab[0x118]; buf.hw[5] = *(s16 *)&tab[0x11a];
  buf.hw[6] = *(s16 *)&tab[0x11c];
  buf.cmds = buf.entries;
  fl = 0xc010040;
  buf.flags = fl;
  fl |= param_4;
  buf.flags = fl;
  if (fl & 1) {
    if (param_1 != 0) {
      buf.pos[0] = lbl_803E15D8 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E15D8 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E15D8 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E15D8 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E15D8 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E15D8 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0xe,tab,0xc,&tab[0x8c],0x586,0);
}

void dll_AA_func03(double param_1,undefined4 param_2,undefined param_3,int param_4,undefined4 param_5)
{
  double scaleAsDouble;
  f32 scale;

  scale = lbl_803E1600;
  if (param_4 != 0) {
    param_1 = (double)*(f32 *)(param_4 + 8);
    scale = (f32)(param_1 / (double)lbl_803E1604);
  }

  scaleAsDouble = (double)scale;
  (*(code *)(*gModgfxInterface + 0x34))(param_1,param_2,param_3,0x15,1,0);
  (*(code *)(*gModgfxInterface + 0x4c))(&DAT_80319344);
  (*(code *)(*gModgfxInterface + 0x54))(param_5);
  (*(code *)(*gModgfxInterface + 0x38))();
  (*(code *)(*gModgfxInterface + 0x3c))
            ((double)lbl_803E1608,(double)lbl_803E160C,(double)lbl_803E160C,4,0x15,
             &DAT_80319318);
  (*(code *)(*gModgfxInterface + 0x3c))
            ((double)lbl_803E1610,(double)lbl_803E1614,(double)lbl_803E1610,2,0x15,
             &DAT_80319318);
  (*(code *)(*gModgfxInterface + 0x3c))
            ((double)lbl_803E160C,(double)lbl_803E1618,(double)lbl_803E160C,0x400000,0,0);
  (*(code *)(*gModgfxInterface + 0x40))();
  (*(code *)(*gModgfxInterface + 0x3c))
            ((double)lbl_803E161C,(double)lbl_803E160C,(double)lbl_803E160C,4,7,&DAT_803192dc);
  (*(code *)(*gModgfxInterface + 0x40))();
  (*(code *)(*gModgfxInterface + 0x3c))
            ((double)lbl_803E1620,(double)lbl_803E160C,(double)lbl_803E160C,4,7,&DAT_803192dc);
  (*(code *)(*gModgfxInterface + 0x3c))
            (scaleAsDouble,(double)lbl_803E1624,scaleAsDouble,2,0x15,&DAT_80319318);
  (*(code *)(*gModgfxInterface + 0x40))();
  scaleAsDouble = (double)lbl_803E160C;
  (*(code *)(*gModgfxInterface + 0x3c))
            (scaleAsDouble,scaleAsDouble,scaleAsDouble,4,7,&DAT_803192dc);
  (*(code *)(*gModgfxInterface + 0x50))
            (param_4,&DAT_80319168,0x15,&DAT_8031923c,0x18,0x3e9,0);
  (*(code *)(*gModgfxInterface + 0x58))();
}


/* Trivial 4b 0-arg blr leaves. */
void dll_9D_func01_nop(void) {}
void dll_9D_func00_nop(void) {}
void dll_9E_func01_nop(void) {}
void dll_9E_func00_nop(void) {}
void dll_9F_func01_nop(void) {}
void dll_9F_func00_nop(void) {}
void dll_A0_func01_nop(void) {}
void dll_A0_func00_nop(void) {}
void dll_A1_func01_nop(void) {}
void dll_A1_func00_nop(void) {}
void dll_A2_func01_nop(void) {}
void dll_A2_func00_nop(void) {}
void DummyA4_release(void) {}
void DummyA4_initialise(void) {}
void dll_A5_func01_nop(void) {}
void dll_A5_func00_nop(void) {}
void dll_A6_func01_nop(void) {}
void dll_A6_func00_nop(void) {}
void dll_A7_func01_nop(void) {}
void dll_A7_func00_nop(void) {}
void dll_A8_func01_nop(void) {}
void dll_A8_func00_nop(void) {}
void dll_A9_func01_nop(void) {}
void dll_A9_func00_nop(void) {}
void dll_AA_func01_nop(void) {}
void dll_AA_func00_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int DummyA4_func03_ret_0(void) { return 0x0; }
