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
extern int FUN_80286834();
extern int FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();

extern undefined4 DAT_80317c48;
extern undefined4 DAT_80317cfc;
extern undefined DAT_80317d5c;
extern undefined DAT_80317d70;
extern undefined DAT_80317d98;
extern undefined DAT_80317dd0;
extern undefined4 DAT_80317ddc;
extern undefined4 DAT_80317dde;
extern undefined4 DAT_80317de0;
extern undefined4 DAT_80317de2;
extern undefined4 DAT_80317de4;
extern undefined4 DAT_80317de6;
extern undefined4 DAT_80317de8;
extern undefined4 DAT_80317e10;
extern undefined4 DAT_80317e4c;
extern undefined DAT_80317e64;
extern undefined DAT_80317e70;
extern undefined4 DAT_80317e7c;
extern undefined4 DAT_80317e7e;
extern undefined4 DAT_80317e80;
extern undefined4 DAT_80317e82;
extern undefined4 DAT_80317e84;
extern undefined4 DAT_80317e86;
extern undefined4 DAT_80317e88;
extern undefined4 DAT_80317eb0;
extern undefined4 DAT_80317f84;
extern undefined DAT_80318060;
extern undefined4 DAT_803180a8;
extern undefined4 DAT_803180aa;
extern undefined4 DAT_803180ac;
extern undefined4 DAT_803180ae;
extern undefined4 DAT_803180b0;
extern undefined4 DAT_803180b2;
extern undefined4 DAT_803180b4;
extern undefined4 DAT_803180d8;
extern undefined4 DAT_80318114;
extern undefined DAT_8031812c;
extern undefined DAT_80318138;
extern undefined4 DAT_80318144;
extern undefined4 DAT_80318146;
extern undefined4 DAT_80318148;
extern undefined4 DAT_8031814a;
extern undefined4 DAT_8031814c;
extern undefined4 DAT_8031814e;
extern undefined4 DAT_80318150;
extern undefined4 DAT_80318178;
extern undefined4 DAT_803181c8;
extern undefined DAT_803181f8;
extern undefined4 DAT_80318208;
extern undefined4 DAT_8031820a;
extern undefined4 DAT_8031820c;
extern undefined4 DAT_8031820e;
extern undefined4 DAT_80318210;
extern undefined4 DAT_80318212;
extern undefined4 DAT_80318214;
extern undefined4 DAT_80318238;
extern undefined4 DAT_8031830c;
extern undefined DAT_8031839c;
extern undefined DAT_803183e8;
extern undefined4 DAT_80318430;
extern undefined4 DAT_80318432;
extern undefined4 DAT_80318434;
extern undefined4 DAT_80318436;
extern undefined4 DAT_80318438;
extern undefined4 DAT_8031843a;
extern undefined4 DAT_8031843c;
extern undefined4 DAT_80318460;
extern undefined4 DAT_8031849c;
extern undefined DAT_803184b4;
extern undefined DAT_803184c0;
extern undefined4 DAT_803184cc;
extern undefined4 DAT_803184ce;
extern undefined4 DAT_803184d0;
extern undefined4 DAT_803184d2;
extern undefined4 DAT_803184d4;
extern undefined4 DAT_803184d6;
extern undefined4 DAT_803184d8;
extern undefined DAT_80318500;
extern undefined DAT_803185b4;
extern undefined4 DAT_80318668;
extern undefined DAT_803186dc;
extern undefined4 DAT_80318714;
extern undefined4 DAT_80318716;
extern undefined4 DAT_80318718;
extern undefined4 DAT_8031871a;
extern undefined4 DAT_8031871c;
extern undefined4 DAT_8031871e;
extern undefined4 DAT_80318720;
extern undefined4 DAT_80318748;
extern undefined4 DAT_80318784;
extern undefined DAT_8031879c;
extern undefined DAT_803187a8;
extern undefined4 DAT_803187b4;
extern undefined4 DAT_803187b6;
extern undefined4 DAT_803187b8;
extern undefined4 DAT_803187ba;
extern undefined4 DAT_803187bc;
extern undefined4 DAT_803187be;
extern undefined4 DAT_803187c0;
extern undefined DAT_803dc588;
extern undefined DAT_803dc590;
extern undefined DAT_803dc598;
extern undefined DAT_803dc5a0;
extern undefined DAT_803dc5a8;
extern undefined DAT_803dc5b0;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e1ee0;
extern f64 DOUBLE_803e1f60;
extern f32 lbl_803E1E58;
extern f32 lbl_803E1E5C;
extern f32 lbl_803E1E60;
extern f32 lbl_803E1E64;
extern f32 lbl_803E1E68;
extern f32 lbl_803E1E6C;
extern f32 lbl_803E1E70;
extern f32 lbl_803E1E74;
extern f32 lbl_803E1E78;
extern f32 lbl_803E1E7C;
extern f32 lbl_803E1E80;
extern f32 lbl_803E1E84;
extern f32 lbl_803E1E88;
extern f32 lbl_803E1E90;
extern f32 lbl_803E1E94;
extern f32 lbl_803E1E98;
extern f32 lbl_803E1E9C;
extern f32 lbl_803E1EA0;
extern f32 lbl_803E1EA4;
extern f32 lbl_803E1EA8;
extern f32 lbl_803E1EAC;
extern f32 lbl_803E1EB0;
extern f32 lbl_803E1EB4;
extern f32 lbl_803E1EB8;
extern f32 hudElementOpacity;
extern f32 lbl_803E1EC4;
extern f32 lbl_803E1EC8;
extern f32 lbl_803E1ECC;
extern f32 lbl_803E1ED0;
extern f32 lbl_803E1ED4;
extern f32 lbl_803E1ED8;
extern f32 lbl_803E1EE8;
extern f32 lbl_803E1EEC;
extern f32 lbl_803E1EF0;
extern f32 lbl_803E1EF4;
extern f32 lbl_803E1EF8;
extern f32 lbl_803E1EFC;
extern f32 lbl_803E1F00;
extern f32 lbl_803E1F04;
extern f32 lbl_803E1F08;
extern f32 lbl_803E1F0C;
extern f32 lbl_803E1F10;
extern f32 lbl_803E1F18;
extern f32 lbl_803E1F1C;
extern f32 lbl_803E1F20;
extern f32 lbl_803E1F24;
extern f32 lbl_803E1F28;
extern f32 lbl_803E1F2C;
extern f32 lbl_803E1F30;
extern f32 lbl_803E1F34;
extern f32 lbl_803E1F38;
extern f32 lbl_803E1F40;
extern f32 lbl_803E1F44;
extern f32 lbl_803E1F48;
extern f32 lbl_803E1F4C;
extern f32 lbl_803E1F50;
extern f32 lbl_803E1F54;
extern f32 lbl_803E1F58;
extern f32 lbl_803E1F68;
extern f32 lbl_803E1F6C;
extern f32 lbl_803E1F70;
extern f32 lbl_803E1F74;
extern f32 lbl_803E1F78;
extern f32 lbl_803E1F7C;
extern f32 lbl_803E1F80;
extern f32 lbl_803E1F84;
extern f32 lbl_803E1F88;
extern f32 lbl_803E1F8C;
extern f32 lbl_803E1F90;
extern f32 lbl_803E1F98;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FA4;
extern f32 lbl_803E1FA8;
extern f32 lbl_803E1FAC;
extern f32 lbl_803E1FB0;
extern f32 lbl_803E1FB4;
extern f32 lbl_803E1FB8;
extern f32 lbl_803E1FBC;
extern f32 lbl_803E1FC0;
extern f32 lbl_803E1FC4;
extern f32 lbl_803E1FC8;
extern f32 lbl_803E1FCC;
extern f32 lbl_803E1FD0;
extern f32 lbl_803E1FD4;
extern f32 lbl_803E1FD8;
extern f32 lbl_803E1FDC;
extern f32 lbl_803E1FE0;
extern f32 lbl_803E1FE4;
extern f32 lbl_803E1FE8;

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


/*
 * --INFO--
 *
 * Function: FUN_800fa644
 * EN v1.0 Address: 0x800FA644
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FAC94
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa644(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  
  local_2cc = lbl_803E1E90;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_80317e70;
  local_308 = 4;
  local_304 = lbl_803E1E94;
  local_300 = lbl_803E1E94;
  local_2fc = lbl_803E1E94;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc590;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = lbl_803E1E98;
  }
  else {
    local_2ec = lbl_803E1E9C;
  }
  local_2e8 = lbl_803E1E94;
  local_2e4 = lbl_803E1E94;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_80317e64;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = lbl_803E1EA0 * local_2cc;
  }
  else {
    local_2cc = lbl_803E1EA4 * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_80317e64;
  local_2c0 = 0x4000;
  local_2bc = lbl_803E1EA8;
  local_2b8 = lbl_803E1E90;
  local_2b4 = lbl_803E1E94;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_80317e64;
  local_2a8 = 2;
  local_2a4 = lbl_803E1EAC;
  local_2a0 = lbl_803E1EAC;
  local_29c = lbl_803E1EB0;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_80317e64;
  local_290 = 0x4000;
  local_28c = lbl_803E1EA8;
  local_288 = lbl_803E1E90;
  local_284 = lbl_803E1E94;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_80317e64;
  local_278 = 2;
  local_274 = lbl_803E1EB4;
  local_270 = lbl_803E1EB4;
  local_26c = lbl_803E1E90;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_80317e64;
  local_260 = 0x4000;
  local_25c = lbl_803E1EA8;
  local_258 = lbl_803E1E90;
  local_254 = lbl_803E1E94;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc590;
  local_248 = 4;
  local_244 = lbl_803E1E94;
  local_240 = lbl_803E1E94;
  local_23c = lbl_803E1E94;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E1E94;
  local_338 = lbl_803E1E94;
  local_334 = lbl_803E1E94;
  local_348 = lbl_803E1E94;
  local_344 = lbl_803E1E94;
  local_340 = lbl_803E1E94;
  local_330 = lbl_803E1EB8;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_80317e7c;
  local_320 = DAT_80317e7e;
  local_31e = DAT_80317e80;
  local_31c = DAT_80317e82;
  local_31a = DAT_80317e84;
  local_318 = DAT_80317e86;
  local_316 = DAT_80317e88;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = lbl_803E1E94 + *(float *)(param_3 + 0xc);
          local_338 = lbl_803E1E94 + *(float *)(param_3 + 0x10);
          local_334 = lbl_803E1E94 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = lbl_803E1E94 + *(float *)(param_1 + 0x18);
        local_338 = lbl_803E1E94 + *(float *)(param_1 + 0x1c);
        local_334 = lbl_803E1E94 + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = lbl_803E1E94 + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1E94 + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E1E94 + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80317e10,4,&DAT_80317e4c,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa6a8
 * EN v1.0 Address: 0x800FA6A8
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800FB044
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa6a8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
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
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined auStack_298 [624];
  undefined4 local_28;
  uint uStack_24;
  
  iVar2 = FUN_8028683c();
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80318060;
  local_328 = 4;
  local_324 = hudElementOpacity;
  local_320 = hudElementOpacity;
  local_31c = hudElementOpacity;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80318060;
  local_310 = 2;
  uStack_24 = randomGetRange(0,10);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_30c = lbl_803E1EC8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1ee0) +
              lbl_803E1EC4;
  local_308 = lbl_803E1ECC;
  local_2e2 = 1;
  local_2e4 = 0x15;
  local_2e8 = &DAT_80318060;
  local_2f8 = 4;
  local_2f4 = lbl_803E1ED0;
  local_2f0 = hudElementOpacity;
  local_2ec = hudElementOpacity;
  local_2ca = 1;
  local_2cc = 0x15;
  local_2d0 = &DAT_80318060;
  local_2e0 = 0x4000;
  local_2dc = lbl_803E1ED4;
  local_2d8 = hudElementOpacity;
  local_2d4 = hudElementOpacity;
  local_2b2 = 2;
  local_2b4 = 0x15;
  local_2b8 = &DAT_80318060;
  local_2c8 = 4;
  local_2c4 = hudElementOpacity;
  local_2c0 = hudElementOpacity;
  local_2bc = hudElementOpacity;
  local_29a = 2;
  local_29c = 0x15;
  local_2a0 = &DAT_80318060;
  local_2b0 = 0x4000;
  local_2ac = lbl_803E1ED4;
  local_2a8 = hudElementOpacity;
  local_2a4 = hudElementOpacity;
  local_330 = 0;
  local_35c = hudElementOpacity;
  local_358 = hudElementOpacity;
  local_354 = hudElementOpacity;
  local_368 = hudElementOpacity;
  local_364 = hudElementOpacity;
  local_360 = hudElementOpacity;
  local_350 = lbl_803E1ED8;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)(auStack_298 + -(int)&local_328) / 0x18 +
          ((int)(auStack_298 + -(int)&local_328) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803180a8;
  local_340 = DAT_803180aa;
  local_33e = DAT_803180ac;
  local_33c = DAT_803180ae;
  local_33a = DAT_803180b0;
  local_338 = DAT_803180b2;
  local_336 = DAT_803180b4;
  local_334 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = hudElementOpacity + *(float *)(param_3 + 0xc);
      local_358 = hudElementOpacity + *(float *)(param_3 + 0x10);
      local_354 = hudElementOpacity + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = hudElementOpacity + *(float *)(iVar2 + 0xc);
      local_358 = hudElementOpacity + *(float *)(iVar2 + 0x10);
      local_354 = hudElementOpacity + *(float *)(iVar2 + 0x14);
    }
  }
  local_388 = &local_328;
  local_384 = iVar2;
  local_344 = extraout_r4;
  local_304 = local_30c;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80317eb0,0x18,&DAT_80317f84,0x89,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa720
 * EN v1.0 Address: 0x800FA720
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FB314
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa720(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  
  local_2cc = lbl_803E1EE8;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_80318138;
  local_308 = 4;
  local_304 = lbl_803E1EEC;
  local_300 = lbl_803E1EEC;
  local_2fc = lbl_803E1EEC;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc598;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = lbl_803E1EF0;
  }
  else {
    local_2ec = lbl_803E1EF4;
  }
  local_2e8 = lbl_803E1EEC;
  local_2e4 = lbl_803E1EEC;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_8031812c;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = lbl_803E1EF8 * local_2cc;
  }
  else {
    local_2cc = lbl_803E1EFC * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_8031812c;
  local_2c0 = 0x4000;
  local_2bc = lbl_803E1F00;
  local_2b8 = lbl_803E1EE8;
  local_2b4 = lbl_803E1EEC;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_8031812c;
  local_2a8 = 2;
  local_2a4 = lbl_803E1F04;
  local_2a0 = lbl_803E1F04;
  local_29c = lbl_803E1F08;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_8031812c;
  local_290 = 0x4000;
  local_28c = lbl_803E1F00;
  local_288 = lbl_803E1EE8;
  local_284 = lbl_803E1EEC;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_8031812c;
  local_278 = 2;
  local_274 = lbl_803E1F0C;
  local_270 = lbl_803E1F0C;
  local_26c = lbl_803E1EE8;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_8031812c;
  local_260 = 0x4000;
  local_25c = lbl_803E1F00;
  local_258 = lbl_803E1EE8;
  local_254 = lbl_803E1EEC;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc598;
  local_248 = 4;
  local_244 = lbl_803E1EEC;
  local_240 = lbl_803E1EEC;
  local_23c = lbl_803E1EEC;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E1EEC;
  local_338 = lbl_803E1EEC;
  local_334 = lbl_803E1EEC;
  local_348 = lbl_803E1EEC;
  local_344 = lbl_803E1EEC;
  local_340 = lbl_803E1EEC;
  local_330 = lbl_803E1F10;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_80318144;
  local_320 = DAT_80318146;
  local_31e = DAT_80318148;
  local_31c = DAT_8031814a;
  local_31a = DAT_8031814c;
  local_318 = DAT_8031814e;
  local_316 = DAT_80318150;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = lbl_803E1EEC + *(float *)(param_3 + 0xc);
          local_338 = lbl_803E1EEC + *(float *)(param_3 + 0x10);
          local_334 = lbl_803E1EEC + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = lbl_803E1EEC + *(float *)(param_1 + 0x18);
        local_338 = lbl_803E1EEC + *(float *)(param_1 + 0x1c);
        local_334 = lbl_803E1EEC + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = lbl_803E1EEC + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1EEC + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E1EEC + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_803180d8,4,&DAT_80318114,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa784
 * EN v1.0 Address: 0x800FA784
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FB6C4
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa784(int param_1,undefined2 param_2,int param_3)
{
  int iVar1;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  undefined4 local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined auStack_260 [604];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 8;
  local_2f8 = &DAT_803181f8;
  local_308 = 2;
  local_304 = lbl_803E1F18;
  local_300 = lbl_803E1F1C;
  local_2fc = lbl_803E1F18;
  local_2da = 0;
  local_2dc = 4;
  local_2e0 = &DAT_803dc5a0;
  local_2f0 = 8;
  local_2ec = lbl_803E1F20;
  local_2e8 = lbl_803E1F20;
  local_2e4 = lbl_803E1F24;
  local_2c2 = 0;
  local_2c4 = 4;
  local_2c8 = &DAT_803181f8;
  local_2d8 = 8;
  local_2d4 = lbl_803E1F20;
  local_2d0 = lbl_803E1F28;
  local_2cc = lbl_803E1F24;
  local_2aa = 0;
  local_2ac = 0;
  local_2b0 = 0;
  local_2c0 = 0x400000;
  local_2bc = lbl_803E1F24;
  local_2b8 = lbl_803E1F2C;
  local_2b4 = lbl_803E1F24;
  local_292 = 1;
  local_294 = 8;
  local_298 = &DAT_803181f8;
  local_2a8 = 2;
  local_2a4 = lbl_803E1F30;
  local_2a0 = lbl_803E1F30;
  local_29c = lbl_803E1F30;
  local_27a = 1;
  local_27c = 0;
  local_280 = 0;
  local_290 = 0x400000;
  local_28c = lbl_803E1F24;
  local_288 = lbl_803E1F34;
  local_284 = lbl_803E1F24;
  local_262 = 2;
  local_264 = 8;
  local_268 = &DAT_803181f8;
  local_278 = 4;
  local_274 = lbl_803E1F24;
  local_270 = lbl_803E1F24;
  local_26c = lbl_803E1F24;
  local_310 = 0;
  local_33c = lbl_803E1F24;
  local_338 = lbl_803E1F24;
  local_334 = lbl_803E1F24;
  local_348 = lbl_803E1F24;
  local_344 = lbl_803E1F24;
  local_340 = lbl_803E1F24;
  local_330 = lbl_803E1F38;
  local_328 = 1;
  local_32c = 0;
  local_30f = 8;
  local_30e = 0;
  local_30d = 0x3c;
  iVar1 = (int)(auStack_260 + -(int)local_368) / 0x18 +
          ((int)(auStack_260 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80318208;
  local_320 = DAT_8031820a;
  local_31e = DAT_8031820c;
  local_31c = DAT_8031820e;
  local_31a = DAT_80318210;
  local_318 = DAT_80318212;
  local_316 = DAT_80318214;
  local_314 = 0x4002400;
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,8,&DAT_80318178,8,&DAT_803181c8,0x46,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa7e8
 * EN v1.0 Address: 0x800FA7E8
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800FB9BC
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa7e8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
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
  undefined local_32b;
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
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
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
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_28;
  uint uStack_24;
  
  iVar1 = FUN_8028683c();
  uVar2 = GameBit_Get(0x63c);
  if (uVar2 == 0) {
    local_312 = 0;
    local_314 = 0x15;
    local_318 = &DAT_803183e8;
    local_328 = 4;
    local_324 = lbl_803E1F40;
    local_320 = lbl_803E1F40;
    local_31c = lbl_803E1F40;
    local_2fa = 0;
    local_2fc = 0x15;
    local_300 = &DAT_803183e8;
    local_310 = 2;
    uVar2 = GameBit_Get(0x4e9);
    if (uVar2 == 0) {
      uStack_24 = randomGetRange(5,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_30c = lbl_803E1F48 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1f60)
      ;
    }
    else {
      local_30c = lbl_803E1F44;
    }
    local_308 = lbl_803E1F4C;
    local_304 = local_30c;
    local_2e2 = 1;
    local_2e4 = 7;
    local_2e8 = &DAT_8031839c;
    local_2f8 = 2;
    local_2f4 = lbl_803E1F50;
    local_2f0 = lbl_803E1F54;
    local_2ec = lbl_803E1F50;
    local_2ca = 1;
    local_2cc = 0x15;
    local_2d0 = &DAT_803183e8;
    local_2e0 = 4;
    local_2dc = lbl_803E1F58;
    local_2d8 = lbl_803E1F40;
    local_2d4 = lbl_803E1F40;
    local_2b2 = 1;
    local_2b4 = 0x15;
    local_2b8 = &DAT_803183e8;
    local_2c8 = 0x4000;
    local_2c4 = lbl_803E1F40;
    local_2c0 = lbl_803E1F50;
    local_2bc = lbl_803E1F40;
    local_29a = 2;
    local_29c = 0x15;
    local_2a0 = &DAT_803183e8;
    local_2b0 = 4;
    local_2ac = lbl_803E1F40;
    local_2a8 = lbl_803E1F40;
    local_2a4 = lbl_803E1F40;
    local_282 = 2;
    local_284 = 0x15;
    local_288 = &DAT_803183e8;
    local_298 = 0x4000;
    local_294 = lbl_803E1F40;
    local_290 = lbl_803E1F50;
    local_28c = lbl_803E1F40;
    local_330 = 0;
    local_35c = lbl_803E1F40;
    local_358 = lbl_803E1F40;
    local_354 = lbl_803E1F40;
    local_368 = lbl_803E1F40;
    local_364 = lbl_803E1F40;
    local_360 = lbl_803E1F40;
    local_350 = lbl_803E1F50;
    local_348 = 2;
    local_34c = 7;
    local_32f = 0xe;
    local_32e = 0;
    local_32d = 0;
    local_32b = 7;
    local_342 = DAT_80318430;
    local_340 = DAT_80318432;
    local_33e = DAT_80318434;
    local_33c = DAT_80318436;
    local_33a = DAT_80318438;
    local_338 = DAT_8031843a;
    local_336 = DAT_8031843c;
    local_388 = &local_328;
    local_334 = param_4 | 0xc0104c0;
    if ((param_4 & 1) != 0) {
      if (iVar1 == 0) {
        local_35c = lbl_803E1F40 + *(float *)(param_3 + 0xc);
        local_358 = lbl_803E1F40 + *(float *)(param_3 + 0x10);
        local_354 = lbl_803E1F40 + *(float *)(param_3 + 0x14);
      }
      else {
        local_35c = lbl_803E1F40 + *(float *)(iVar1 + 0xc);
        local_358 = lbl_803E1F40 + *(float *)(iVar1 + 0x10);
        local_354 = lbl_803E1F40 + *(float *)(iVar1 + 0x14);
      }
    }
    local_384 = iVar1;
    local_344 = extraout_r4;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80318238,0x18,&DAT_8031830c,0x89,0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa880
 * EN v1.0 Address: 0x800FA880
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FBCDC
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa880(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  
  local_2cc = lbl_803E1F68;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803184c0;
  local_308 = 4;
  local_304 = lbl_803E1F6C;
  local_300 = lbl_803E1F6C;
  local_2fc = lbl_803E1F6C;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc5a8;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = lbl_803E1F70;
  }
  else {
    local_2ec = lbl_803E1F74;
  }
  local_2e8 = lbl_803E1F6C;
  local_2e4 = lbl_803E1F6C;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_803184b4;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = lbl_803E1F78 * local_2cc;
  }
  else {
    local_2cc = lbl_803E1F7C * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_803184b4;
  local_2c0 = 0x4000;
  local_2bc = lbl_803E1F80;
  local_2b8 = lbl_803E1F68;
  local_2b4 = lbl_803E1F6C;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_803184b4;
  local_2a8 = 2;
  local_2a4 = lbl_803E1F84;
  local_2a0 = lbl_803E1F84;
  local_29c = lbl_803E1F88;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_803184b4;
  local_290 = 0x4000;
  local_28c = lbl_803E1F80;
  local_288 = lbl_803E1F68;
  local_284 = lbl_803E1F6C;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_803184b4;
  local_278 = 2;
  local_274 = lbl_803E1F8C;
  local_270 = lbl_803E1F8C;
  local_26c = lbl_803E1F68;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_803184b4;
  local_260 = 0x4000;
  local_25c = lbl_803E1F80;
  local_258 = lbl_803E1F68;
  local_254 = lbl_803E1F6C;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc5a8;
  local_248 = 4;
  local_244 = lbl_803E1F6C;
  local_240 = lbl_803E1F6C;
  local_23c = lbl_803E1F6C;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E1F6C;
  local_338 = lbl_803E1F6C;
  local_334 = lbl_803E1F6C;
  local_348 = lbl_803E1F6C;
  local_344 = lbl_803E1F6C;
  local_340 = lbl_803E1F6C;
  local_330 = lbl_803E1F90;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_803184cc;
  local_320 = DAT_803184ce;
  local_31e = DAT_803184d0;
  local_31c = DAT_803184d2;
  local_31a = DAT_803184d4;
  local_318 = DAT_803184d6;
  local_316 = DAT_803184d8;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = lbl_803E1F6C + *(float *)(param_3 + 0xc);
          local_338 = lbl_803E1F6C + *(float *)(param_3 + 0x10);
          local_334 = lbl_803E1F6C + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = lbl_803E1F6C + *(float *)(param_1 + 0x18);
        local_338 = lbl_803E1F6C + *(float *)(param_1 + 0x1c);
        local_334 = lbl_803E1F6C + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = lbl_803E1F6C + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1F6C + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E1F6C + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80318460,4,&DAT_8031849c,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa8e4
 * EN v1.0 Address: 0x800FA8E4
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x800FC08C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa8e4(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int param_6)
{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined *puVar4;
  undefined8 uVar5;
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
  short local_330;
  short local_32e;
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
  
  uVar5 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  puVar4 = &DAT_80318500;
  uVar2 = randomGetRange(0,0x1e);
  DAT_80318716 = (short)uVar2 + 0x1e;
  local_302 = 0;
  local_304 = 0x12;
  local_308 = &DAT_803186dc;
  local_318 = 4;
  local_314 = lbl_803E1F98;
  local_310 = lbl_803E1F98;
  local_30c = lbl_803E1F98;
  local_2ea = 0;
  local_2ec = 0x12;
  local_2f0 = &DAT_803186dc;
  local_300 = 2;
  local_2fc = lbl_803E1F9C;
  local_2f4 = lbl_803E1F9C;
  local_2f8 = lbl_803E1FA0;
  local_2d2 = 1;
  local_2d4 = 0x12;
  local_2d8 = &DAT_803186dc;
  local_2e8 = 4;
  local_2e4 = lbl_803E1FA4;
  local_2e0 = lbl_803E1F98;
  local_2dc = lbl_803E1F98;
  local_2ba = 1;
  local_2bc = 0x12;
  local_2c0 = &DAT_803186dc;
  local_2d0 = 0x400000;
  local_2cc = lbl_803E1F98;
  if (param_6 == 0) {
    local_2c8 = lbl_803E1FAC;
  }
  else {
    local_2c8 = lbl_803E1FA8;
  }
  local_2c4 = lbl_803E1F98;
  local_2a2 = 1;
  local_2a4 = 0x12;
  local_2a8 = &DAT_803186dc;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E1F98;
  if (param_6 == 0) {
    local_2b0 = lbl_803E1FB4;
  }
  else {
    local_2b0 = lbl_803E1FB0;
  }
  local_2ac = lbl_803E1F98;
  local_28a = 2;
  local_28c = 0x12;
  local_290 = &DAT_803186dc;
  local_2a0 = 4;
  local_29c = lbl_803E1F98;
  local_298 = lbl_803E1F98;
  local_294 = lbl_803E1F98;
  local_272 = 2;
  local_274 = 0x12;
  local_278 = &DAT_803186dc;
  local_288 = 0x400000;
  local_284 = lbl_803E1F98;
  if (param_6 == 0) {
    local_280 = lbl_803E1FAC;
  }
  else {
    local_280 = lbl_803E1FA8;
  }
  local_27c = lbl_803E1F98;
  local_25a = 2;
  local_25c = 0x12;
  local_260 = &DAT_803186dc;
  local_270 = 0x4000;
  local_26c = lbl_803E1F98;
  if (param_6 == 0) {
    local_268 = lbl_803E1FB4;
  }
  else {
    local_268 = lbl_803E1FB0;
  }
  local_264 = lbl_803E1F98;
  local_242 = 2;
  local_244 = 0x12;
  local_248 = &DAT_803186dc;
  local_258 = 2;
  local_254 = lbl_803E1FB0;
  local_250 = lbl_803E1FB0;
  local_24c = lbl_803E1FB0;
  local_320 = 0;
  local_334 = (undefined2)uVar5;
  local_34c = lbl_803E1F98;
  if (param_6 == 0) {
    local_348 = lbl_803E1FBC;
  }
  else {
    local_348 = lbl_803E1FB8;
  }
  local_344 = lbl_803E1F98;
  local_358 = lbl_803E1F98;
  local_354 = lbl_803E1F98;
  local_350 = lbl_803E1F98;
  local_340 = lbl_803E1FB0;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0x12;
  local_31e = 0;
  local_31d = 0x10;
  local_31b = 9;
  local_332 = DAT_80318714;
  local_32c = DAT_8031871a;
  local_32a = DAT_8031871c;
  local_328 = DAT_8031871e;
  local_326 = DAT_80318720;
  local_378 = &local_318;
  local_324 = param_4 | 0x4080400;
  if ((param_4 & 1) != 0) {
    if (iVar1 == 0) {
      local_34c = lbl_803E1F98 + *(float *)(param_3 + 0xc);
      local_348 = local_348 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1F98 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1F98 + *(float *)(iVar1 + 0x18);
      local_348 = local_348 + *(float *)(iVar1 + 0x1c);
      local_344 = lbl_803E1F98 + *(float *)(iVar1 + 0x20);
    }
  }
  if ((int)uVar5 == 0) {
    uVar3 = 0x3e9;
  }
  else if ((int)uVar5 == 1) {
    uVar3 = 0x3f0;
  }
  else {
    uVar3 = 0x3f3;
  }
  if (param_6 != 0) {
    puVar4 = &DAT_803185b4;
  }
  DAT_80318718 = DAT_80318716;
  local_374 = iVar1;
  local_330 = DAT_80318716;
  local_32e = DAT_80318716;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x12,puVar4,0x10,&DAT_80318668,uVar3,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa9c0
 * EN v1.0 Address: 0x800FA9C0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FC4A4
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa9c0(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  
  local_2cc = lbl_803E1FC0;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803187a8;
  local_308 = 4;
  local_304 = lbl_803E1FC4;
  local_300 = lbl_803E1FC4;
  local_2fc = lbl_803E1FC4;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc5b0;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = lbl_803E1FC8;
  }
  else {
    local_2ec = lbl_803E1FCC;
  }
  local_2e8 = lbl_803E1FC4;
  local_2e4 = lbl_803E1FC4;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_8031879c;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = lbl_803E1FD0 * local_2cc;
  }
  else {
    local_2cc = lbl_803E1FD4 * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_8031879c;
  local_2c0 = 0x4000;
  local_2bc = lbl_803E1FD8;
  local_2b8 = lbl_803E1FC0;
  local_2b4 = lbl_803E1FC4;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_8031879c;
  local_2a8 = 2;
  local_2a4 = lbl_803E1FDC;
  local_2a0 = lbl_803E1FDC;
  local_29c = lbl_803E1FE0;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_8031879c;
  local_290 = 0x4000;
  local_28c = lbl_803E1FD8;
  local_288 = lbl_803E1FC0;
  local_284 = lbl_803E1FC4;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_8031879c;
  local_278 = 2;
  local_274 = lbl_803E1FE4;
  local_270 = lbl_803E1FE4;
  local_26c = lbl_803E1FC0;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_8031879c;
  local_260 = 0x4000;
  local_25c = lbl_803E1FD8;
  local_258 = lbl_803E1FC0;
  local_254 = lbl_803E1FC4;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc5b0;
  local_248 = 4;
  local_244 = lbl_803E1FC4;
  local_240 = lbl_803E1FC4;
  local_23c = lbl_803E1FC4;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E1FC4;
  local_338 = lbl_803E1FC4;
  local_334 = lbl_803E1FC4;
  local_348 = lbl_803E1FC4;
  local_344 = lbl_803E1FC4;
  local_340 = lbl_803E1FC4;
  local_330 = lbl_803E1FE8;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_803187b4;
  local_320 = DAT_803187b6;
  local_31e = DAT_803187b8;
  local_31c = DAT_803187ba;
  local_31a = DAT_803187bc;
  local_318 = DAT_803187be;
  local_316 = DAT_803187c0;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = lbl_803E1FC4 + *(float *)(param_3 + 0xc);
          local_338 = lbl_803E1FC4 + *(float *)(param_3 + 0x10);
          local_334 = lbl_803E1FC4 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = lbl_803E1FC4 + *(float *)(param_1 + 0x18);
        local_338 = lbl_803E1FC4 + *(float *)(param_1 + 0x1c);
        local_334 = lbl_803E1FC4 + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = lbl_803E1FC4 + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1FC4 + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E1FC4 + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80318748,4,&DAT_80318784,0x3c,0);
  return;
}


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
