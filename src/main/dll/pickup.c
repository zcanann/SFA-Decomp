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
  GfxCmd entries[13];  /* +0x60 */
} GfxBuf;

void dll_9D_func03(int param_1,undefined4 param_2,int param_3,uint param_4)
{
  GfxBuf buf;
  GfxCmd *e = buf.entries;

  e[0].layer = 0;  e[0].flags = 0x15; e[0].tex = &lbl_80318038[432]; e[0].mode = 4;
  e[0].x = lbl_803E2078; e[0].y = lbl_803E2078; e[0].z = lbl_803E2078;
  e[1].layer = 0;  e[1].flags = 7;    e[1].tex = &lbl_80318038[356]; e[1].mode = 2;
  e[1].x = lbl_803E207C; e[1].y = lbl_803E2080; e[1].z = lbl_803E207C;
  e[2].layer = 0;  e[2].flags = 7;    e[2].tex = &lbl_80318038[372]; e[2].mode = 2;
  e[2].x = lbl_803E2080; e[2].y = lbl_803E2080; e[2].z = lbl_803E2080;
  e[3].layer = 0;  e[3].flags = 7;    e[3].tex = &lbl_80318038[388]; e[3].mode = 2;
  e[3].x = lbl_803E207C; e[3].y = lbl_803E2080; e[3].z = lbl_803E207C;
  e[4].layer = 0;  e[4].flags = 0;    e[4].tex = (void *)0;          e[4].mode = 0x400000;
  e[4].x = lbl_803E2078; e[4].y = lbl_803E2084; e[4].z = lbl_803E2078;
  e[5].layer = 1;  e[5].flags = 7;    e[5].tex = &lbl_80318038[372]; e[5].mode = 4;
  e[5].x = lbl_803E2088; e[5].y = lbl_803E2078; e[5].z = lbl_803E2078;
  e[6].layer = 1;  e[6].flags = 0x15; e[6].tex = &lbl_80318038[432]; e[6].mode = 0x4000;
  e[6].x = lbl_803E2078; e[6].y = lbl_803E2078; e[6].z = lbl_803E2078;
  e[7].layer = 1;  e[7].flags = 0;    e[7].tex = (void *)0;          e[7].mode = 0x400000;
  e[7].x = lbl_803E2078; e[7].y = lbl_803E208C; e[7].z = lbl_803E2078;
  e[8].layer = 2;  e[8].flags = 0x15; e[8].tex = &lbl_80318038[432]; e[8].mode = 0x4000;
  e[8].x = lbl_803E2078; e[8].y = lbl_803E2078; e[8].z = lbl_803E2078;
  e[9].layer = 2;  e[9].flags = 0;    e[9].tex = (void *)0;          e[9].mode = 0x400000;
  e[9].x = lbl_803E2078; e[9].y = lbl_803E2090; e[9].z = lbl_803E2078;
  e[10].layer = 3; e[10].flags = 0x15; e[10].tex = &lbl_80318038[432]; e[10].mode = 0x4000;
  e[10].x = lbl_803E2078; e[10].y = lbl_803E2078; e[10].z = lbl_803E2078;
  e[11].layer = 3; e[11].flags = 0;    e[11].tex = (void *)0;          e[11].mode = 0x400000;
  e[11].x = lbl_803E2078; e[11].y = lbl_803E208C; e[11].z = lbl_803E2078;
  e[12].layer = 3; e[12].flags = 7;    e[12].tex = &lbl_80318038[372]; e[12].mode = 4;
  e[12].x = lbl_803E2078; e[12].y = lbl_803E2078; e[12].z = lbl_803E2078;

  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E2078; buf.pos[1] = lbl_803E2078; buf.pos[2] = lbl_803E2078;
  buf.col[0] = lbl_803E2078; buf.col[1] = lbl_803E2078; buf.col[2] = lbl_803E2078;
  buf.scale = lbl_803E2094;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = 13;
  buf.hw[0] = *(s16 *)&lbl_80318038[504]; buf.hw[1] = *(s16 *)&lbl_80318038[506];
  buf.hw[2] = *(s16 *)&lbl_80318038[508]; buf.hw[3] = *(s16 *)&lbl_80318038[510];
  buf.hw[4] = *(s16 *)&lbl_80318038[512]; buf.hw[5] = *(s16 *)&lbl_80318038[514];
  buf.hw[6] = *(s16 *)&lbl_80318038[516];
  buf.cmds = buf.entries;
  buf.flags = param_4 | 0xc0100c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      buf.pos[0] = lbl_803E2078 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E2078 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E2078 + *(f32 *)(param_3 + 0x14);
    } else {
      buf.pos[0] = lbl_803E2078 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E2078 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E2078 + *(f32 *)(param_1 + 0x20);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,0x15,lbl_80318038,0x18,&lbl_80318038[212],0x46c,0);
}

/*
 * --INFO--
 *
 * Function: dll_9E_func03
 * EN v1.0 Address: 0x800FD7B0
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FDD34
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_9E_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
    GfxCmd entries[14];
  } buf;
  GfxCmd *e = buf.entries;
  int ctx;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &DAT_80319060; e[0].mode = 4;
  e[0].x = lbl_803E2098; e[0].y = lbl_803E2098; e[0].z = lbl_803E2098;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &DAT_80319060; e[1].mode = 2;
  e[1].x = lbl_803E209C; e[1].y = lbl_803E20A0; e[1].z = lbl_803E209C;
  e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x400000;
  e[2].x = lbl_803E2098; e[2].y = lbl_803E20A4; e[2].z = lbl_803E2098;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = &DAT_80319060; e[3].mode = 2;
  e[3].x = lbl_803E20A8; e[3].y = lbl_803E20A8; e[3].z = lbl_803E20A8;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = &DAT_80319024; e[4].mode = 4;
  e[4].x = lbl_803E20AC; e[4].y = lbl_803E2098; e[4].z = lbl_803E2098;
  e[5].layer = 1; e[5].flags = 0x15; e[5].tex = &DAT_80319060; e[5].mode = 0x4000;
  e[5].x = lbl_803E20B0; e[5].y = lbl_803E2098; e[5].z = lbl_803E2098;
  e[6].layer = 1; e[6].flags = 0; e[6].tex = (void *)0; e[6].mode = 0x400000;
  e[6].x = lbl_803E2098; e[6].y = lbl_803E2098; e[6].z = lbl_803E2098;
  e[7].layer = 2; e[7].flags = 0x7a; e[7].tex = (void *)0; e[7].mode = 0x10000;
  e[7].x = lbl_803E2098; e[7].y = lbl_803E2098; e[7].z = lbl_803E2098;
  e[8].layer = 2; e[8].flags = 0x15; e[8].tex = &DAT_80319060; e[8].mode = 8;
  e[8].x = lbl_803E20B4; e[8].y = lbl_803E20B8; e[8].z = lbl_803E2098;
  e[9].layer = 2; e[9].flags = 0x15; e[9].tex = &DAT_80319060; e[9].mode = 0x4000;
  e[9].x = lbl_803E20B0; e[9].y = lbl_803E2098; e[9].z = lbl_803E2098;
  e[10].layer = 2; e[10].flags = 0; e[10].tex = (void *)0; e[10].mode = 0x400000;
  e[10].x = lbl_803E2098; e[10].y = lbl_803E20BC; e[10].z = lbl_803E2098;
  e[11].layer = 3; e[11].flags = 0x15; e[11].tex = &DAT_80319060; e[11].mode = 0x4000;
  e[11].x = lbl_803E20B0; e[11].y = lbl_803E2098; e[11].z = lbl_803E2098;
  e[12].layer = 3; e[12].flags = 0; e[12].tex = (void *)0; e[12].mode = 0x400000;
  e[12].x = lbl_803E2098; e[12].y = lbl_803E20BC; e[12].z = lbl_803E2098;
  e[13].layer = 3; e[13].flags = 7; e[13].tex = &DAT_80319024; e[13].mode = 4;
  e[13].x = lbl_803E2098; e[13].y = lbl_803E2098; e[13].z = lbl_803E2098;

  buf.v58 = 0;
  ctx = FUN_80286840();
  buf.ctx = ctx;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E2098; buf.pos[1] = lbl_803E2098; buf.pos[2] = lbl_803E2098;
  buf.col[0] = lbl_803E2098; buf.col[1] = lbl_803E2098; buf.col[2] = lbl_803E2098;
  buf.scale = lbl_803E20C0;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = 14;
  buf.hw[0] = DAT_803190a8; buf.hw[1] = DAT_803190aa; buf.hw[2] = DAT_803190ac;
  buf.hw[3] = DAT_803190ae; buf.hw[4] = DAT_803190b0; buf.hw[5] = DAT_803190b2;
  buf.hw[6] = DAT_803190b4;
  buf.cmds = buf.entries;
  buf.flags = param_4 | 0xc0100c0;
  if ((param_4 & 1) != 0) {
    if (ctx == 0) {
      buf.pos[0] = lbl_803E2098 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E2098 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E2098 + *(f32 *)(param_3 + 0x14);
    } else {
      buf.pos[0] = lbl_803E2098 + *(f32 *)(ctx + 0x18);
      buf.pos[1] = lbl_803E2098 + *(f32 *)(ctx + 0x1c);
      buf.pos[2] = lbl_803E2098 + *(f32 *)(ctx + 0x20);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,0x15,&DAT_80318eb0,0x18,&DAT_80318f84,0x46c,0);
  FUN_8028688c();
}

/*
 * --INFO--
 *
 * Function: FUN_800fd81c
 * EN v1.0 Address: 0x800FD81C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800FE0B4
 * EN v1.1 Size: 1064b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fd81c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
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
void dll_A0_func03(int param_1,int param_2,int param_3,uint param_4)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_803194b0;
  local_318 = 4;
  local_314 = lbl_803E2108;
  local_310 = lbl_803E2108;
  local_30c = lbl_803E2108;
  if (param_2 == 0) {
    local_2f8 = lbl_803E2110;
  }
  else {
    local_2f8 = lbl_803E2114;
  }
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_803194b0;
  local_2fc = lbl_803E210C;
  local_300 = 2;
  local_2d2 = 1;
  local_2d4 = 0x15;
  local_2d8 = &DAT_803194b0;
  local_2e8 = 2;
  local_2e4 = lbl_803E2118;
  local_2e0 = lbl_803E2118;
  local_2dc = lbl_803E2118;
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80319474;
  local_2d0 = 4;
  local_2cc = lbl_803E211C;
  local_2c8 = lbl_803E2108;
  local_2c4 = lbl_803E2108;
  local_2a2 = 1;
  local_2a4 = 0x15;
  local_2a8 = &DAT_803194b0;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E2120;
  local_2b0 = lbl_803E2124;
  local_2ac = lbl_803E2108;
  local_28a = 2;
  local_28c = 7;
  local_290 = &DAT_80319474;
  local_2a0 = 2;
  local_29c = lbl_803E2128;
  local_298 = lbl_803E2124;
  local_294 = lbl_803E2128;
  local_272 = 2;
  local_274 = 7;
  local_278 = &DAT_80319484;
  local_288 = 2;
  local_284 = lbl_803E212C;
  local_280 = lbl_803E2124;
  local_27c = lbl_803E212C;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_803194b0;
  local_270 = 0x4000;
  local_26c = lbl_803E2120;
  local_268 = lbl_803E2124;
  local_264 = lbl_803E2108;
  local_242 = 3;
  local_244 = 7;
  local_248 = &DAT_80319474;
  local_258 = 4;
  local_254 = lbl_803E2108;
  local_250 = lbl_803E2108;
  local_24c = lbl_803E2108;
  local_22a = 3;
  local_22c = 0x15;
  local_230 = &DAT_803194b0;
  local_240 = 0x4000;
  local_23c = lbl_803E2130;
  local_238 = lbl_803E2124;
  local_234 = lbl_803E2108;
  local_320 = 0;
  local_334 = (undefined2)param_2;
  local_34c = lbl_803E2108;
  local_348 = lbl_803E2108;
  local_344 = lbl_803E2108;
  local_358 = lbl_803E2108;
  local_354 = lbl_803E2108;
  local_350 = lbl_803E2108;
  local_340 = lbl_803E2124;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 10;
  local_332 = DAT_803194f8;
  local_330 = DAT_803194fa;
  local_32e = DAT_803194fc;
  local_32c = DAT_803194fe;
  local_32a = DAT_80319500;
  local_328 = DAT_80319502;
  local_326 = DAT_80319504;
  local_378 = &local_318;
  local_324 = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E2108 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E2108 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E2108 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E2108 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E2108 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E2108 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_2f4 = local_2fc;
  (**(code **)(*gModgfxInterface + 8))(&local_378,0,0x15,&DAT_80319300,0x18,&DAT_803193d4,0x1d9,0);
  return;
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
void dll_A1_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
    GfxCmd entries[14];
  } buf;
  GfxCmd *e = buf.entries;
  int ctx;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &DAT_803196d8; e[0].mode = 4;
  e[0].x = lbl_803E2138; e[0].y = lbl_803E2138; e[0].z = lbl_803E2138;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &DAT_803196d8; e[1].mode = 2;
  e[1].x = lbl_803E213C; e[1].y = lbl_803E213C; e[1].z = lbl_803E2140;
  e[2].layer = 1; e[2].flags = 0x15; e[2].tex = &DAT_803196d8; e[2].mode = 4;
  e[2].x = lbl_803E2144; e[2].y = lbl_803E2138; e[2].z = lbl_803E2138;
  e[3].layer = 1; e[3].flags = 0x15; e[3].tex = &DAT_803196d8; e[3].mode = 0x4000;
  e[3].x = lbl_803E2148; e[3].y = lbl_803E214C; e[3].z = lbl_803E2138;
  e[4].layer = 1; e[4].flags = 0x15; e[4].tex = &DAT_803196d8; e[4].mode = 2;
  e[4].x = lbl_803E2150; e[4].y = lbl_803E2150; e[4].z = lbl_803E2154;
  e[5].layer = 2; e[5].flags = 0x15; e[5].tex = &DAT_803196d8; e[5].mode = 0x4000;
  e[5].x = lbl_803E2148; e[5].y = lbl_803E214C; e[5].z = lbl_803E2138;
  e[6].layer = 3; e[6].flags = 1; e[6].tex = (void *)0; e[6].mode = 0x2000;
  e[6].x = lbl_803E2138; e[6].y = lbl_803E2138; e[6].z = lbl_803E2138;
  e[7].layer = 4; e[7].flags = 0x15; e[7].tex = &DAT_803196d8; e[7].mode = 2;
  e[7].x = lbl_803E2158; e[7].y = lbl_803E2158; e[7].z = lbl_803E2148;
  e[8].layer = 4; e[8].flags = 0x15; e[8].tex = &DAT_803196d8; e[8].mode = 0x4000;
  e[8].x = lbl_803E2148; e[8].y = lbl_803E214C; e[8].z = lbl_803E2138;
  e[9].layer = 4; e[9].flags = 0x6dd; e[9].tex = (void *)0; e[9].mode = 0x800000;
  e[9].x = lbl_803E2148; e[9].y = lbl_803E2138; e[9].z = lbl_803E2138;
  e[10].layer = 5; e[10].flags = 0x15; e[10].tex = &DAT_803196d8; e[10].mode = 0x4000;
  e[10].x = lbl_803E2148; e[10].y = lbl_803E214C; e[10].z = lbl_803E2138;
  e[11].layer = 5; e[11].flags = 0x6de; e[11].tex = (void *)0; e[11].mode = 0x800000;
  e[11].x = lbl_803E2150; e[11].y = lbl_803E2138; e[11].z = lbl_803E2138;
  e[12].layer = 5; e[12].flags = 0x6dd; e[12].tex = (void *)0; e[12].mode = 0x800000;
  e[12].x = lbl_803E2148; e[12].y = lbl_803E2138; e[12].z = lbl_803E2138;
  e[13].layer = 6; e[13].flags = 4; e[13].tex = (void *)0; e[13].mode = 0x2000;
  e[13].x = lbl_803E2138; e[13].y = lbl_803E2138; e[13].z = lbl_803E2138;

  buf.v58 = 0;
  ctx = FUN_8028683c();
  buf.ctx = ctx;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E2138; buf.pos[1] = lbl_803E2138; buf.pos[2] = lbl_803E2138;
  buf.col[0] = lbl_803E2138; buf.col[1] = lbl_803E2138; buf.col[2] = lbl_803E2138;
  buf.scale = lbl_803E215C;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = 14;
  buf.hw[0] = DAT_80319720; buf.hw[1] = DAT_80319722; buf.hw[2] = DAT_80319724; buf.hw[3] = DAT_80319726;
  buf.hw[4] = DAT_80319728; buf.hw[5] = DAT_8031972a; buf.hw[6] = DAT_8031972c;
  buf.cmds = buf.entries;
  buf.flags = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (ctx == 0) {
      buf.pos[0] = lbl_803E2138 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E2138 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E2138 + *(f32 *)(param_3 + 0x14);
    } else {
      buf.pos[0] = lbl_803E2138 + *(f32 *)(ctx + 0x18);
      buf.pos[1] = lbl_803E2138 + *(f32 *)(ctx + 0x1c);
      buf.pos[2] = lbl_803E2138 + *(f32 *)(ctx + 0x20);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,0x15,&DAT_80319528,0x18,&DAT_803195fc,0x203,0);
  FUN_8028683c();
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
void dll_A2_func03(int param_1,undefined2 param_2,int param_3,uint param_4)
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
    GfxCmd entries[12];
  } buf;
  GfxCmd *e = buf.entries;
  int ctx;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = &DAT_80319900; e[0].mode = 4;
  e[0].x = lbl_803E2160; e[0].y = lbl_803E2160; e[0].z = lbl_803E2160;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = &DAT_80319900; e[1].mode = 2;
  e[1].x = lbl_803E2164; e[1].y = lbl_803E2164; e[1].z = lbl_803E2168;
  e[2].layer = 0; e[2].flags = 7; e[2].tex = &DAT_803198b4; e[2].mode = 8;
  e[2].x = lbl_803E216C; e[2].y = lbl_803E2160; e[2].z = lbl_803E2160;
  e[3].layer = 1; e[3].flags = 7; e[3].tex = &DAT_803198c4; e[3].mode = 2;
  e[3].x = lbl_803E2170; e[3].y = lbl_803E2170; e[3].z = lbl_803E2174;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = &DAT_803198d4; e[4].mode = 2;
  e[4].x = lbl_803E2174; e[4].y = lbl_803E2174; e[4].z = lbl_803E2178;
  e[5].layer = 1; e[5].flags = 7; e[5].tex = &DAT_803198c4; e[5].mode = 4;
  e[5].x = lbl_803E216C; e[5].y = lbl_803E2160; e[5].z = lbl_803E2160;
  e[6].layer = 1; e[6].flags = 0x15; e[6].tex = &DAT_80319900; e[6].mode = 0x4000;
  e[6].x = lbl_803E217C; e[6].y = lbl_803E2180; e[6].z = lbl_803E2160;
  e[7].layer = 2; e[7].flags = 7; e[7].tex = &DAT_803198c4; e[7].mode = 2;
  e[7].x = lbl_803E217C; e[7].y = lbl_803E217C; e[7].z = lbl_803E217C;
  e[8].layer = 2; e[8].flags = 7; e[8].tex = &DAT_803198d4; e[8].mode = 2;
  e[8].x = lbl_803E217C; e[8].y = lbl_803E217C; e[8].z = lbl_803E217C;
  e[9].layer = 2; e[9].flags = 0x15; e[9].tex = &DAT_80319900; e[9].mode = 0x4000;
  e[9].x = lbl_803E217C; e[9].y = lbl_803E2180; e[9].z = lbl_803E2160;
  e[10].layer = 3; e[10].flags = 7; e[10].tex = &DAT_803198c4; e[10].mode = 4;
  e[10].x = lbl_803E2160; e[10].y = lbl_803E2160; e[10].z = lbl_803E2160;
  e[11].layer = 3; e[11].flags = 0x15; e[11].tex = &DAT_80319900; e[11].mode = 0x4000;
  e[11].x = lbl_803E217C; e[11].y = lbl_803E2180; e[11].z = lbl_803E2160;

  buf.v58 = 0;
  ctx = param_1;
  buf.ctx = ctx;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E2160; buf.pos[1] = lbl_803E2160; buf.pos[2] = lbl_803E2160;
  buf.col[0] = lbl_803E2160; buf.col[1] = lbl_803E2160; buf.col[2] = lbl_803E2160;
  buf.scale = lbl_803E217C;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = 12;
  buf.hw[0] = DAT_80319948; buf.hw[1] = DAT_8031994a; buf.hw[2] = DAT_8031994c; buf.hw[3] = DAT_8031994e;
  buf.hw[4] = DAT_80319950; buf.hw[5] = DAT_80319952; buf.hw[6] = DAT_80319954;
  buf.cmds = buf.entries;
  buf.flags = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (ctx == 0) {
      buf.pos[0] = lbl_803E2160 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E2160 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E2160 + *(f32 *)(param_3 + 0x14);
    } else {
      buf.pos[0] = lbl_803E2160 + *(f32 *)(ctx + 0x18);
      buf.pos[1] = lbl_803E2160 + *(f32 *)(ctx + 0x1c);
      buf.pos[2] = lbl_803E2160 + *(f32 *)(ctx + 0x20);
    }
  }
  (**(code **)(*gModgfxInterface + 8))(&buf,0,0x15,&DAT_80319750,0x18,&DAT_80319824,0x24,0);
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
void dll_A5_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_388;
  short *local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined4 local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined4 local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined4 local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined4 local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined auStack_1f0 [456];
  undefined4 local_28;
  uint uStack_24;
  
  local_384 = (short *)FUN_80286840();
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 8;
  local_318 = &DAT_80319a00;
  local_328 = 4;
  local_324 = lbl_803E2188;
  local_320 = lbl_803E2188;
  local_31c = lbl_803E2188;
  local_2fa = 0;
  local_2fc = 4;
  local_300 = &DAT_803dc5d0;
  local_310 = 2;
  local_30c = lbl_803E218C;
  local_308 = lbl_803E218C;
  local_304 = lbl_803E2190;
  local_2e2 = 0;
  local_2e4 = 4;
  local_2e8 = &DAT_803dc5d8;
  local_2f8 = 2;
  local_2f4 = lbl_803E2194;
  local_2f0 = lbl_803E2194;
  local_2ec = lbl_803E2190;
  local_2ca = 0;
  local_2cc = 0;
  local_2d0 = 0;
  local_2e0 = 0x80;
  local_2dc = lbl_803E2188;
  local_2d8 = lbl_803E2188;
  uStack_24 = (int)*local_384 ^ 0x80000000;
  local_28 = 0x43300000;
  local_2d4 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e21a8);
  local_2b2 = 0;
  local_2b4 = 0x7a;
  local_2b8 = 0;
  local_2c8 = 0x10000;
  local_2c4 = lbl_803E2188;
  local_2c0 = lbl_803E2188;
  local_2bc = lbl_803E2188;
  local_29a = 1;
  local_29c = 8;
  local_2a0 = &DAT_80319a00;
  local_2b0 = 4;
  local_2ac = lbl_803E2198;
  local_2a8 = lbl_803E2188;
  local_2a4 = lbl_803E2188;
  local_282 = 1;
  local_284 = 0;
  local_288 = 0;
  local_298 = 0x400000;
  local_294 = lbl_803E2188;
  local_290 = lbl_803E2188;
  local_28c = lbl_803E218C;
  local_26a = 1;
  local_26c = 8;
  local_270 = &DAT_80319a00;
  local_280 = 2;
  local_27c = lbl_803E218C;
  local_278 = lbl_803E218C;
  local_274 = lbl_803E219C;
  local_252 = 1;
  local_254 = 0x3a1;
  local_258 = 0;
  local_268 = 0x1800000;
  local_264 = lbl_803E218C;
  local_260 = lbl_803E2188;
  local_25c = lbl_803E21A0;
  local_23a = 2;
  local_23c = 0x7a;
  local_240 = 0;
  local_250 = 0x10000;
  local_24c = lbl_803E2188;
  local_248 = lbl_803E2188;
  local_244 = lbl_803E2188;
  local_222 = 2;
  local_224 = 8;
  local_228 = &DAT_80319a00;
  local_238 = 4;
  local_234 = lbl_803E2188;
  local_230 = lbl_803E2188;
  local_22c = lbl_803E2188;
  local_20a = 2;
  local_20c = 0;
  local_210 = 0;
  local_220 = 0x400000;
  local_21c = lbl_803E2188;
  local_218 = lbl_803E2188;
  local_214 = lbl_803E21A4;
  local_1f2 = 2;
  local_1f4 = 0x3a0;
  local_1f8 = 0;
  local_208 = 0x800000;
  local_204 = lbl_803E218C;
  local_200 = lbl_803E2188;
  local_1fc = lbl_803E2188;
  local_330 = (undefined)extraout_r4;
  local_35c = lbl_803E2188;
  local_358 = lbl_803E2188;
  local_354 = lbl_803E2188;
  local_368 = lbl_803E2188;
  local_364 = lbl_803E2188;
  local_360 = lbl_803E2188;
  local_350 = lbl_803E218C;
  local_348 = 1;
  local_34c = 0;
  local_32f = 8;
  local_32e = 0;
  local_32d = 0x3c;
  iVar1 = (int)(auStack_1f0 + -(int)local_388) / 0x18 +
          ((int)(auStack_1f0 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80319a10;
  local_340 = DAT_80319a12;
  local_33e = DAT_80319a14;
  local_33c = DAT_80319a16;
  local_33a = DAT_80319a18;
  local_338 = DAT_80319a1a;
  local_336 = DAT_80319a1c;
  local_334 = param_4 | 0x4040080;
  if ((param_4 & 1) != 0) {
    if (local_384 == (short *)0x0) {
      local_35c = lbl_803E2188 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E2188 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E2188 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E2188 + *(float *)(local_384 + 0xc);
      local_358 = lbl_803E2188 + *(float *)(local_384 + 0xe);
      local_354 = lbl_803E2188 + *(float *)(local_384 + 0x10);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*gModgfxInterface + 8))(&local_388,0,8,&DAT_80319998,4,&DAT_803199e8,0x5e0,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fd9c0
 * EN v1.0 Address: 0x800FD9C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800FF2A0
 * EN v1.1 Size: 1692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fd9c0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
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
 * EN v1.0 Address: 0x800FD9C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FFDE0
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_A8_func03(int param_1,undefined2 param_2,int param_3,uint param_4,undefined4 param_5,
                 int param_6)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined4 local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  
  local_29c = lbl_803E221C;
  if (param_6 != 0) {
    local_29c = lbl_803E2218;
  }
  local_302 = 0;
  local_304 = 0xe;
  local_308 = &DAT_80319c2c;
  local_318 = 4;
  local_314 = lbl_803E2220;
  local_310 = lbl_803E2220;
  local_30c = lbl_803E2220;
  if (param_6 == 0) {
    local_2e0 = lbl_803E2230;
    local_2dc = lbl_803E2234;
  }
  else {
    local_2e0 = lbl_803E2228;
    local_2dc = lbl_803E222C;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_80319c1c;
  local_2e8 = 2;
  local_2ea = 0;
  local_2ec = 7;
  local_2f0 = &DAT_80319c0c;
  local_2fc = lbl_803E2224;
  local_300 = 2;
  local_2ba = 1;
  local_2bc = 0xe;
  local_2c0 = &DAT_80319c2c;
  local_2d0 = 2;
  local_2cc = lbl_803E2238;
  local_2c8 = lbl_803E223C;
  local_2c4 = lbl_803E2238;
  local_2a2 = 1;
  local_2a4 = 0xe;
  local_2a8 = &DAT_80319c2c;
  local_2b8 = 4;
  local_2b4 = lbl_803E2240;
  local_2b0 = lbl_803E2220;
  local_2ac = lbl_803E2220;
  local_28a = 1;
  local_28c = 0xe;
  local_290 = &DAT_80319c2c;
  local_2a0 = 0x4000;
  local_298 = lbl_803E2220;
  local_294 = lbl_803E2220;
  local_272 = 2;
  local_274 = 0xe;
  local_278 = &DAT_80319c2c;
  local_288 = 0x4000;
  local_280 = lbl_803E2220;
  local_27c = lbl_803E2220;
  local_25a = 3;
  local_25c = 1;
  local_260 = 0;
  local_270 = 0x2000;
  local_26c = lbl_803E2220;
  local_268 = lbl_803E2220;
  local_264 = lbl_803E2220;
  local_242 = 4;
  local_244 = 0xe;
  local_248 = &DAT_80319c2c;
  local_258 = 4;
  local_254 = lbl_803E2220;
  local_250 = lbl_803E2220;
  local_24c = lbl_803E2220;
  local_22a = 4;
  local_22c = 0xe;
  local_230 = &DAT_80319c2c;
  local_240 = 0x4000;
  local_238 = lbl_803E2220;
  local_234 = lbl_803E2220;
  local_212 = 4;
  local_214 = 0xe;
  local_218 = &DAT_80319c2c;
  local_228 = 2;
  local_224 = lbl_803E2238;
  local_220 = lbl_803E2244;
  local_21c = lbl_803E2238;
  local_320 = 0;
  local_34c = lbl_803E2220;
  local_348 = lbl_803E2248;
  local_344 = lbl_803E2220;
  local_358 = lbl_803E2220;
  local_354 = lbl_803E2220;
  local_350 = lbl_803E2220;
  local_340 = lbl_803E2238;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xb;
  local_332 = DAT_80319c48;
  local_330 = DAT_80319c4a;
  local_32e = DAT_80319c4c;
  local_32c = DAT_80319c4e;
  local_32a = DAT_80319c50;
  local_328 = DAT_80319c52;
  local_326 = DAT_80319c54;
  local_378 = &local_318;
  local_324 = param_4 | 0xc010040;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E2220 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E2248 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E2220 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E2220 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E2248 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E2220 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  local_2f8 = local_2e0;
  local_2f4 = local_2fc;
  local_2e4 = local_2dc;
  local_284 = local_29c;
  local_23c = local_29c;
  (**(code **)(*gModgfxInterface + 8))(&local_378,0,0xe,&DAT_80319b38,0xc,&DAT_80319bc4,0x586,0);
  return;
}

/*
 * --INFO--
 *
 * Function: dll_A9_func03
 * EN v1.0 Address: 0x800FDA2C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801001A0
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_A9_func03(int param_1,undefined2 param_2,int param_3,uint param_4,undefined4 param_5,
                 int param_6)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined4 local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  
  local_29c = lbl_803E2254;
  if (param_6 != 0) {
    local_29c = lbl_803E2250;
  }
  local_302 = 0;
  local_304 = 0xe;
  local_308 = &DAT_80319d6c;
  local_318 = 4;
  local_314 = lbl_803E2258;
  local_310 = lbl_803E2258;
  local_30c = lbl_803E2258;
  if (param_6 == 0) {
    local_2e0 = lbl_803E2268;
    local_2dc = lbl_803E226C;
  }
  else {
    local_2e0 = lbl_803E2260;
    local_2dc = lbl_803E2264;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_80319d5c;
  local_2e8 = 2;
  local_2ea = 0;
  local_2ec = 7;
  local_2f0 = &DAT_80319d4c;
  local_2fc = lbl_803E225C;
  local_300 = 2;
  local_2ba = 1;
  local_2bc = 0xe;
  local_2c0 = &DAT_80319d6c;
  local_2d0 = 2;
  local_2cc = lbl_803E2270;
  local_2c8 = lbl_803E2274;
  local_2c4 = lbl_803E2270;
  local_2a2 = 1;
  local_2a4 = 0xe;
  local_2a8 = &DAT_80319d6c;
  local_2b8 = 4;
  local_2b4 = lbl_803E2278;
  local_2b0 = lbl_803E2258;
  local_2ac = lbl_803E2258;
  local_28a = 1;
  local_28c = 0xe;
  local_290 = &DAT_80319d6c;
  local_2a0 = 0x4000;
  local_298 = lbl_803E2258;
  local_294 = lbl_803E2258;
  local_272 = 2;
  local_274 = 0xe;
  local_278 = &DAT_80319d6c;
  local_288 = 0x4000;
  local_280 = lbl_803E2258;
  local_27c = lbl_803E2258;
  local_25a = 3;
  local_25c = 1;
  local_260 = 0;
  local_270 = 0x2000;
  local_26c = lbl_803E2258;
  local_268 = lbl_803E2258;
  local_264 = lbl_803E2258;
  local_242 = 4;
  local_244 = 0xe;
  local_248 = &DAT_80319d6c;
  local_258 = 4;
  local_254 = lbl_803E2258;
  local_250 = lbl_803E2258;
  local_24c = lbl_803E2258;
  local_22a = 4;
  local_22c = 0xe;
  local_230 = &DAT_80319d6c;
  local_240 = 0x4000;
  local_238 = lbl_803E2258;
  local_234 = lbl_803E2258;
  local_212 = 4;
  local_214 = 0xe;
  local_218 = &DAT_80319d6c;
  local_228 = 2;
  local_224 = lbl_803E2270;
  local_220 = lbl_803E227C;
  local_21c = lbl_803E2270;
  local_320 = 0;
  local_34c = lbl_803E2258;
  local_348 = lbl_803E2258;
  local_344 = lbl_803E2258;
  local_358 = lbl_803E2258;
  local_354 = lbl_803E2258;
  local_350 = lbl_803E2258;
  local_340 = lbl_803E2270;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xb;
  local_332 = DAT_80319d88;
  local_330 = DAT_80319d8a;
  local_32e = DAT_80319d8c;
  local_32c = DAT_80319d8e;
  local_32a = DAT_80319d90;
  local_328 = DAT_80319d92;
  local_326 = DAT_80319d94;
  local_378 = &local_318;
  local_324 = param_4 | 0xc010040;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E2258 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E2258 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E2258 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E2258 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E2258 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E2258 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  local_2f8 = local_2e0;
  local_2f4 = local_2fc;
  local_2e4 = local_2dc;
  local_284 = local_29c;
  local_23c = local_29c;
  (**(code **)(*gModgfxInterface + 8))(&local_378,0,0xe,&DAT_80319c78,0xc,&DAT_80319d04,0x586,0);
  return;
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
