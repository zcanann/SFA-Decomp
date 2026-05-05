#include "ghidra_import.h"
#include "main/dll/CF/dll_165.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern undefined4 FUN_801899b4();
extern undefined4 FUN_80189cc4();
extern undefined4 FUN_80189e0c();
extern byte FUN_80294c28();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern f32 FLOAT_803e4854;
extern f32 FLOAT_803e4874;
extern f32 FLOAT_803e4898;
extern f32 FLOAT_803e489c;

/*
 * --INFO--
 *
 * Function: staffactivated_init
 * EN v1.0 Address: 0x8018A53C
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x8018A7DC
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staffactivated_init(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,uint param_9)
{
  int iVar1;
  byte bVar3;
  uint uVar2;
  int iVar4;
  int iVar5;
  undefined auStack_28 [4];
  undefined2 local_24;
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar4 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_80017a98();
  if ((*(byte *)(iVar4 + 0x1d) >> 6 & 1) == 0) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if ((*(char *)(iVar4 + 0x1d) < '\0') && (bVar3 = FUN_80294c28(iVar1), bVar3 != 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  bVar3 = *(byte *)(iVar5 + 0x1c);
  if (bVar3 == 2) {
    FUN_80189e0c(param_9,iVar4);
  }
  else {
    if (bVar3 < 2) {
      if (bVar3 == 0) {
        if (((*(byte *)(param_9 + 0xaf) & 4) != 0) && (uVar2 = FUN_80017690(0xd2a), uVar2 == 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
          FUN_80017698(0xd2a,1);
        }
        uVar2 = FUN_80017690(0x957);
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        iVar1 = 0;
        if (((int)*(short *)(iVar5 + 0x22) == 0xffffffff) ||
           (uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x22)), uVar2 != 0)) {
          iVar1 = 1;
        }
        *(byte *)(iVar4 + 0x1d) = (byte)(iVar1 << 7) | *(byte *)(iVar4 + 0x1d) & 0x7f;
        if (-1 < *(char *)(iVar4 + 0x1d)) {
          return;
        }
        local_1c = FLOAT_803e4898;
        local_18 = FLOAT_803e489c;
        local_14 = FLOAT_803e4874;
        local_20 = FLOAT_803e4854;
        local_22 = 0;
        local_24 = 100;
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x7c3,auStack_28,2,0xffffffff,0);
        local_1c = FLOAT_803e4898;
        local_18 = FLOAT_803e489c;
        local_14 = FLOAT_803e4874;
        local_20 = FLOAT_803e4854;
        local_22 = 5;
        local_24 = 10;
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x7c3,auStack_28,2,0xffffffff,0);
        return;
      }
    }
    else if (bVar3 < 6) {
      if (bVar3 < 4) {
        FUN_801899b4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        return;
      }
      FUN_80189cc4(param_9,iVar4);
      return;
    }
    iVar1 = 0;
    if (((int)*(short *)(iVar5 + 0x22) == 0xffffffff) ||
       (uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x22)), uVar2 != 0)) {
      iVar1 = 1;
    }
    *(byte *)(iVar4 + 0x1d) = (byte)(iVar1 << 7) | *(byte *)(iVar4 + 0x1d) & 0x7f;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: treasurechest_getExtraSize
 * EN v1.0 Address: 0x8018A9B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ABD4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treasurechest_getExtraSize(void)
{
  return 1;
}

/*
 * --INFO--
 *
 * Function: treasurechest_func08
 * EN v1.0 Address: 0x8018A9BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ABDC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treasurechest_func08(void)
{
  return 0;
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3C20;
extern void fn_8003B8F4(f32);
#pragma scheduling off
#pragma peephole off
void treasurechest_render(void) { fn_8003B8F4(lbl_803E3C20); }
#pragma peephole reset
#pragma scheduling reset

extern u32 lbl_803DDAE0;
extern void Resource_Release(u32);
#pragma scheduling off
#pragma peephole off
void treasurechest_free(void) { Resource_Release(lbl_803DDAE0); }
#pragma peephole reset
#pragma scheduling reset
