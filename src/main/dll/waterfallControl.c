#include "ghidra_import.h"
#include "main/dll/waterfallControl.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017760();
extern int FUN_800632d8();
extern int FUN_800632f4();

extern f64 DOUBLE_803e3c08;
extern f64 DOUBLE_803e3c28;
extern f32 lbl_803DC074;
extern f32 lbl_803E3BF4;
extern f32 lbl_803E3BF8;
extern f32 lbl_803E3BFC;
extern f32 lbl_803E3C00;
extern f32 lbl_803E3C10;
extern f32 lbl_803E3C14;
extern f32 lbl_803E3C18;
extern f32 lbl_803E3C1C;
extern f32 lbl_803E3C20;

/*
 * --INFO--
 *
 * Function: FUN_80163bbc
 * EN v1.0 Address: 0x80163BBC
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x80163E3C
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163bbc(short *param_1,int param_2)
{
  double dVar1;
  int iVar2;
  float local_58 [20];
  
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) / lbl_803E3BF4;
  iVar2 = FUN_800632d8((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_58,0);
  if (iVar2 != 0) {
    if (local_58[0] <= lbl_803E3BF8) {
      *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - (local_58[0] - lbl_803E3BF8);
      *(float *)(param_1 + 0x14) = lbl_803E3C00;
    }
    else {
      *(float *)(param_1 + 0x14) = lbl_803E3BFC * lbl_803DC074 + *(float *)(param_1 + 0x14);
    }
  }
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) / lbl_803E3BF4;
  iVar2 = (int)*(short *)(param_2 + 0x27c) / 100 + ((int)*(short *)(param_2 + 0x27c) >> 0x1f);
  *(short *)(param_2 + 0x27c) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  iVar2 = (int)*(short *)(param_2 + 0x27e) / 100 + ((int)*(short *)(param_2 + 0x27e) >> 0x1f);
  *(short *)(param_2 + 0x27e) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  iVar2 = (int)*(short *)(param_2 + 0x280) / 100 + ((int)*(short *)(param_2 + 0x280) >> 0x1f);
  *(short *)(param_2 + 0x280) = (short)iVar2 - (short)(iVar2 >> 0x1f);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  dVar1 = DOUBLE_803e3c08;
  param_1[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x27c) ^ 0x80000000)
                                   - DOUBLE_803e3c08) * lbl_803DC074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) -
                                  DOUBLE_803e3c08));
  param_1[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x27e) ^ 0x80000000)
                                   - dVar1) * lbl_803DC074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1
                                  ));
  *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(param_2 + 0x280) ^ 0x80000000) -
                                 dVar1) * lbl_803DC074 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - dVar1));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163e44
 * EN v1.0 Address: 0x80163E44
 * EN v1.0 Size: 1020b
 * EN v1.1 Address: 0x80164068
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163e44(short *param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  undefined4 *local_68 [2];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  local_68[0] = (undefined4 *)0x0;
  dVar7 = (double)lbl_803E3C10;
  iVar1 = FUN_800632f4((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_68,0,0);
  iVar4 = 0;
  iVar5 = 0;
  puVar3 = local_68[0];
  if (0 < iVar1) {
    do {
      dVar6 = (double)(*(float *)(param_1 + 8) - *(float *)*puVar3);
      if (dVar6 < (double)lbl_803E3C00) {
        dVar6 = (double)(float)((double)lbl_803E3C14 * dVar6 + (double)lbl_803E3BF4);
      }
      if (dVar6 < dVar7) {
        iVar5 = iVar4;
        dVar7 = dVar6;
      }
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  if (*(float *)(param_1 + 0x12) <= lbl_803E3C18) {
    if (*(float *)(param_1 + 0x12) < lbl_803E3C14) {
      *(float *)(param_1 + 0x12) = lbl_803E3C14;
    }
  }
  else {
    *(float *)(param_1 + 0x12) = lbl_803E3C18;
  }
  if (*(float *)(param_1 + 0x14) <= lbl_803E3C18) {
    if (*(float *)(param_1 + 0x14) < lbl_803E3C14) {
      *(float *)(param_1 + 0x14) = lbl_803E3C14;
    }
  }
  else {
    *(float *)(param_1 + 0x14) = lbl_803E3C18;
  }
  if (*(float *)(param_1 + 0x16) <= lbl_803E3C18) {
    if (*(float *)(param_1 + 0x16) < lbl_803E3C14) {
      *(float *)(param_1 + 0x16) = lbl_803E3C14;
    }
  }
  else {
    *(float *)(param_1 + 0x16) = lbl_803E3C18;
  }
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  dVar7 = DOUBLE_803e3c08;
  uStack_5c = (int)*(short *)(param_2 + 0x27c) ^ 0x80000000;
  local_60 = 0x43300000;
  uStack_54 = (int)param_1[2] ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e3c08) * lbl_803DC074 +
               (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e3c08));
  local_50 = (longlong)iVar1;
  param_1[2] = (short)iVar1;
  uStack_44 = (int)*(short *)(param_2 + 0x27e) ^ 0x80000000;
  local_48 = 0x43300000;
  uStack_3c = (int)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_44) - dVar7) * lbl_803DC074 +
               (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar7));
  local_38 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack_2c = (int)*(short *)(param_2 + 0x280) ^ 0x80000000;
  local_30 = 0x43300000;
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - dVar7) * lbl_803DC074 +
               (float)((double)CONCAT44(0x43300000,uStack_24) - dVar7));
  local_20 = (double)(longlong)iVar1;
  *param_1 = (short)iVar1;
  if (local_68[0] != (undefined4 *)0x0) {
    if (*(float *)(param_1 + 8) <= lbl_803E3BF8 + *(float *)local_68[0][iVar5]) {
      *(float *)(param_1 + 8) = lbl_803E3BF8 + *(float *)local_68[0][iVar5];
      if (param_1[0x23] == 0x3fb) {
        uVar2 = FUN_80017760(0x8c,0xb4);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack_24 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(lbl_803E3C1C * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3c28) /
              (float)(local_20 - DOUBLE_803e3c08)));
      }
      else {
        uVar2 = FUN_80017760(0x14,0x28);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack_24 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(lbl_803E3C1C * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3c28) /
              (float)(local_20 - DOUBLE_803e3c08)));
      }
      local_28 = 0x43300000;
      iVar5 = (int)(lbl_803E3C20 * *(float *)(param_1 + 0x14));
      local_20 = (double)(longlong)iVar5;
      if (0x7f < iVar5) {
        iVar5 = 0x7f;
      }
      if (0x10 < iVar5) {
        FUN_80006824((uint)param_1,0x27e);
        uVar2 = FUN_80017760(0,5);
        if ((uVar2 == 0) && ((*(byte *)(param_2 + 0x27a) & 8) != 0)) {
          FUN_80006824((uint)param_1,0x27f);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + lbl_803E3BFC;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0F
 * EN v1.0 Address: 0x80163F8C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void tumbleweed_func0F(int obj, int value)
{
  *(int *)(*(int *)(obj + 0xb8) + 0x284) = value;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_setScale
 * EN v1.0 Address: 0x80164070
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int tumbleweed_setScale(int obj)
{
  return *(byte *)(*(int *)(obj + 0xb8) + 0x278);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_getExtraSize
 * EN v1.0 Address: 0x8016407C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int tumbleweed_getExtraSize(void)
{
  return 0x2a4;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0E
 * EN v1.0 Address: 0x80163F98
 * EN v1.0 Size: 24b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int tumbleweed_func0E(int obj)
{
  return *(byte *)(*(int *)(obj + 0xb8) + 0x278) == 6;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0B
 * EN v1.0 Address: 0x80164060
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void tumbleweed_func0B(int obj,float x,float y)
{
  int extra = *(int *)(obj + 0xb8);

  *(float *)(extra + 0x288) = x;
  *(float *)(extra + 0x28c) = y;
}
