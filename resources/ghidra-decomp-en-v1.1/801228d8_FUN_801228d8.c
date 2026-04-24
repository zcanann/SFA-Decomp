// Function: FUN_801228d8
// Entry: 801228d8
// Size: 776 bytes

void FUN_801228d8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short param_11,uint param_12,uint param_13,
                 int *param_14,uint param_15,undefined4 param_16)

{
  int iVar1;
  short extraout_r4;
  uint uVar2;
  int iVar3;
  byte bVar4;
  int *piVar5;
  uint uVar6;
  undefined8 uVar7;
  double dVar8;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  iVar1 = FUN_8028683c();
  local_3c = DAT_803e2a9c;
  local_38 = DAT_803e2aa0;
  local_44 = DAT_803e2aa4;
  local_40 = DAT_803e2aa8;
  if ((param_12 & 0xff) == 0) goto LAB_80122bc8;
  local_30 = (double)CONCAT44(0x43300000,param_13 ^ 0x80000000);
  if ((float)(local_30 - DOUBLE_803e2af8) < FLOAT_803e2c1c) {
LAB_80122988:
    local_30 = (double)CONCAT44(0x43300000,0x23fU - *param_14 ^ 0x80000000);
    dVar8 = (double)FLOAT_803e2c38;
    uVar2 = param_12;
    piVar5 = param_14;
    uVar6 = param_15;
    uVar7 = FUN_80077318((double)(float)(local_30 - DOUBLE_803e2af8),dVar8,(&DAT_803a9610)[iVar1],
                         param_12,0x100);
    if (iVar1 == 0x1e) {
      if ((param_15 & 0xff) == 0) {
        FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_3c,
                     &DAT_803dc7b8,(int)extraout_r4,uVar2,param_13,piVar5,uVar6,param_16);
      }
      else {
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        iVar3 = (int)param_11;
        uVar7 = FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                             (int)&local_3c,s__02d__02d_8031cd00,iVar1,iVar3,param_13,piVar5,uVar6,
                             param_16);
        iVar1 = (int)extraout_r4;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_44,
                     &DAT_803dc7b0,iVar1,iVar3,param_13,piVar5,uVar6,param_16);
      }
    }
    else {
      FUN_8028fde8(uVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_3c,
                   &DAT_803dc7c0,(int)extraout_r4,uVar2,param_13,piVar5,uVar6,param_16);
    }
    iVar1 = FUN_80019b4c();
    FUN_80019b54(3,3);
    FUN_80018728(&local_3c,&local_48,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
    bVar4 = (byte)param_12;
    if (((param_15 & 0xff) == 0) && (param_11 <= extraout_r4)) {
      FUN_80019940(0,0xff,0,bVar4);
    }
    else {
      FUN_80019940(0xff,0xff,0xff,bVar4);
    }
    local_30 = (double)CONCAT44(0x43300000,0x24fU - *param_14 ^ 0x80000000);
    iVar3 = (int)-(FLOAT_803e2af0 * local_48 - (float)(local_30 - DOUBLE_803e2af8));
    local_28 = (double)(longlong)iVar3;
    FUN_80015e00(&local_3c,0x93,iVar3,0x1a9);
    if ((param_15 & 0xff) != 0) {
      if (extraout_r4 < 0) {
        FUN_80019940(0xff,0,0,bVar4);
      }
      else {
        FUN_80019940(0,0xff,0,bVar4);
      }
      local_28 = (double)CONCAT44(0x43300000,0x24fU - *param_14 ^ 0x80000000);
      iVar3 = (int)-(FLOAT_803e2af0 * local_48 - (float)(local_28 - DOUBLE_803e2af8));
      local_30 = (double)(longlong)iVar3;
      FUN_80015e00(&local_44,0x93,iVar3,0x1a9);
    }
    FUN_80019b54(iVar1,3);
  }
  else {
    local_30 = (double)CONCAT44(0x43300000,param_13 ^ 0x80000000);
    if (((FLOAT_803e2c28 < (float)(local_30 - DOUBLE_803e2af8)) || ((param_13 & 8) != 0)) ||
       (iVar1 == 0x1e)) goto LAB_80122988;
  }
  *param_14 = *param_14 + 0x28;
LAB_80122bc8:
  FUN_80286888();
  return;
}

