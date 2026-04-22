#include "ghidra_import.h"
#include "main/dll/SC/SCcollectables.h"

extern undefined4 FUN_8000bb00();
extern undefined4 FUN_8000bb38();
extern undefined8 FUN_80014ba4();
extern uint FUN_80014e9c();
extern uint FUN_80020078();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80038524();
extern undefined4 FUN_80043070();
extern undefined4 FUN_80043604();
extern undefined4 FUN_80043658();
extern undefined8 FUN_80043938();
extern undefined4 FUN_8004832c();
extern uint FUN_800e8024();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80296cb4();

extern undefined DAT_803adca8;
extern undefined4 DAT_803adcb6;
extern undefined4 DAT_803adcba;
extern undefined4 DAT_803adcc3;
extern undefined4 DAT_803dccb8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de874;
extern f64 DOUBLE_803e6128;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60f8;
extern f32 FLOAT_803e60fc;
extern f32 FLOAT_803e6100;
extern f32 FLOAT_803e6104;
extern f32 FLOAT_803e6108;
extern f32 FLOAT_803e610c;
extern f32 FLOAT_803e6110;
extern f32 FLOAT_803e6114;
extern f32 FLOAT_803e6118;
extern f32 FLOAT_803e611c;
extern f32 FLOAT_803e6120;
extern f32 FLOAT_803e6130;

/*
 * --INFO--
 *
 * Function: FUN_801d6f04
 * EN v1.0 Address: 0x801D6F04
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d6f04(int param_1)
{
  float fVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar2 = FUN_8002bac4();
  iVar4 = *(int *)(param_1 + 0xb8);
  local_2c = FLOAT_803e60f8;
  local_28 = FLOAT_803e60fc;
  local_24 = FLOAT_803e60f8;
  local_34 = 0xc0e;
  local_36 = 1;
  if ((*(byte *)(iVar4 + 0xd4) & 4) != 0) {
    fVar1 = *(float *)(iVar4 + 4);
    if (FLOAT_803e6100 <= fVar1) {
      if (FLOAT_803e6108 <= fVar1) {
        if (FLOAT_803e6118 <= fVar1) {
          if (FLOAT_803e6120 <= fVar1) {
            *(float *)(iVar4 + 4) = FLOAT_803e60f8;
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfb;
          }
        }
        else {
          uStack_1c = FUN_80022264(0,0x1e0);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
              *(float *)(iVar4 + 4) * FLOAT_803e6104) {
            (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)(iVar4 + 0xd4) & 2) != 0) {
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e611c;
            for (cVar3 = '\x0f'; cVar3 != '\0'; cVar3 = cVar3 + -1) {
              (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack_1c = FUN_80022264(0,0x1e0);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
            *(float *)(iVar4 + 4) / FLOAT_803e610c) {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e6110 * ((*(float *)(iVar4 + 4) - FLOAT_803e6100) / FLOAT_803e6114);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) | 2;
      }
    }
    else {
      uStack_1c = FUN_80022264(0,0x1e0);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
          *(float *)(iVar4 + 4) * FLOAT_803e6104) {
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) + FLOAT_803dc074;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d71f4
 * EN v1.0 Address: 0x801D71F4
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d71f4(void)
{
  short *psVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  undefined8 extraout_f1;
  float local_28;
  float local_24;
  float local_20 [8];
  
  psVar1 = (short *)FUN_8028683c();
  iVar4 = 0;
  DAT_803adcc3 = '\0';
  DAT_803adcba = '\0';
  FUN_8002fb40(extraout_f1,(double)FLOAT_803dc074);
  if (DAT_803adcba != '\0') {
    *psVar1 = *psVar1 + DAT_803adcb6;
  }
  puVar3 = &DAT_803adca8;
  for (iVar2 = 0; iVar2 < DAT_803adcc3; iVar2 = iVar2 + 1) {
    switch(puVar3[0x13]) {
    case 1:
      iVar4 = 1;
      break;
    case 2:
      iVar4 = 2;
      break;
    case 3:
      iVar4 = 1;
      break;
    case 4:
      iVar4 = 2;
      break;
    case 9:
      FUN_8000bb38((uint)psVar1,0x2f4);
    }
    puVar3 = puVar3 + 1;
  }
  if ((iVar4 != 0) &&
     ((FUN_80038524(psVar1,iVar4 + -1,&local_28,&local_24,local_20,0), psVar1[0x50] != 0x1b ||
      (FLOAT_803e6130 <= *(float *)(psVar1 + 0x4c))))) {
    FUN_8000bb00((double)local_28,(double)local_24,(double)local_20[0],(uint)psVar1,0x415);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7348
 * EN v1.0 Address: 0x801D7348
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d7348(void)
{
  int iVar1;
  
  (**(code **)(*DAT_803dd72c + 0x74))();
  iVar1 = FUN_8002bac4();
  FUN_80296cb4(iVar1,0xff);
  return 2;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7388
 * EN v1.0 Address: 0x801D7388
 * EN v1.0 Size: 796b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801d7388(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)
{
  undefined4 uVar1;
  uint uVar2;
  undefined8 uVar3;
  char local_18;
  char local_17 [19];
  
  FUN_8002bac4();
  uVar3 = FUN_80014ba4(0,local_17,&local_18);
  if (param_11 == 0x17) {
    uVar2 = FUN_800e8024('\x01',0);
    if (('\0' < local_17[0]) && (uVar2 == 0)) {
      FUN_8000bb38(0,0x418);
      return 1;
    }
  }
  else if (param_11 < 0x17) {
    if (param_11 == 0x15) {
      if (('\0' < local_18) && (DAT_803dccb8 == 0)) {
        FUN_8000bb38(0,0x418);
        return 1;
      }
    }
    else if (param_11 < 0x15) {
      if ((0x13 < param_11) && (local_17[0] < '\0')) {
        FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x42);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(7);
        FUN_80043658(uVar1,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,1);
        FUN_8000bb38(0,0x418);
        return 1;
      }
    }
    else if (('\0' < local_17[0]) && (uVar2 = FUN_800e8024('\x01',0), uVar2 != 0)) {
      FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
      uVar1 = FUN_8004832c(0x42);
      FUN_80043658(uVar1,0);
      uVar1 = FUN_8004832c(7);
      FUN_80043658(uVar1,1);
      uVar2 = FUN_80020078(0xbfd);
      if (uVar2 == 0) {
        uVar2 = FUN_80020078(0xff);
        if (uVar2 == 0) {
          uVar2 = FUN_80020078(0xc6e);
          if (uVar2 == 0) {
            uVar2 = FUN_80020078(0xc85);
            if (uVar2 != 0) {
              (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
            }
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
          }
        }
        else {
          (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
        }
      }
      else {
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
      }
      FUN_8000bb38(0,0x418);
      return 1;
    }
  }
  else if (param_11 == 0x19) {
    uVar2 = FUN_80014e9c(0);
    if ((uVar2 & 0x200) != 0) {
      FUN_80043604(0,0,1);
      FUN_8004832c(0x42);
      uVar3 = FUN_80043938(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004832c(0x17);
      FUN_80043938(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8000bb38(0,0x419);
      return 1;
    }
  }
  else if ((param_11 < 0x19) && (DAT_803de874 = 1, '\0' < local_18)) {
    FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,9);
    uVar1 = FUN_8004832c(9);
    FUN_80043658(uVar1,0);
    uVar1 = FUN_8004832c(7);
    FUN_80043658(uVar1,1);
    FUN_8000bb38(0,0x418);
    return 1;
  }
  return 0;
}
