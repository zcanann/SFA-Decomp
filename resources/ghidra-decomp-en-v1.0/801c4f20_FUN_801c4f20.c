// Function: FUN_801c4f20
// Entry: 801c4f20
// Size: 952 bytes

/* WARNING: Removing unreachable block (ram,0x801c505c) */

void FUN_801c4f20(undefined2 *param_1)

{
  byte bVar1;
  float fVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  uVar3 = FUN_8002b9ec();
  if ((*(int *)(param_1 + 0x7a) != 0) &&
     (*(int *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) + -1, *(int *)(param_1 + 0x7a) == 0)) {
    FUN_80088c94(7,1);
    FUN_80008cbc(param_1,uVar3,0x20d,0);
    FUN_80008cbc(param_1,uVar3,0x20e,0);
    FUN_80008cbc(param_1,uVar3,0x222,0);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  }
  uVar4 = FUN_800481b0(0x20);
  FUN_8004350c(uVar4,1,0);
  FUN_801c4664(param_1);
  FUN_801d7ed4(iVar7 + 0x18,8,0xffffffff,0xffffffff,0xae6,10);
  FUN_801d8060(iVar7 + 0x18,4,0xffffffff,0xffffffff,0xcbb,8);
  FUN_801d7ed4(iVar7 + 0x18,0x10,0xffffffff,0xffffffff,0xcbb,0xc4);
  bVar1 = *(byte *)(iVar7 + 0x24);
  if (bVar1 == 3) {
    (**(code **)(*DAT_803dca54 + 0x4c))((int)(short)param_1[0x5a]);
    (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
    *(undefined *)(iVar7 + 0x24) = 4;
    FUN_800200e8(0xae6,0);
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if ((*(uint *)(iVar7 + 0x18) & 1) != 0) {
        param_1[3] = param_1[3] | 0x4000;
        *param_1 = 0;
        *(undefined *)(iVar7 + 0x24) = 2;
        *(uint *)(iVar7 + 0x18) = *(uint *)(iVar7 + 0x18) & 0xfffffffe;
        FUN_800200e8(0xae6,1);
        (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      }
    }
    else if (bVar1 == 0) {
      fVar2 = *(float *)(iVar7 + 0x14) - FLOAT_803db414;
      *(float *)(iVar7 + 0x14) = fVar2;
      if (fVar2 <= FLOAT_803e4f40) {
        FUN_8000bb18(param_1,0x343);
        uVar5 = FUN_800221a0(500,1000);
        *(float *)(iVar7 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e4f38);
      }
      if ((*(byte *)((int)param_1 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar7 + 0x24) = 1;
        (**(code **)(*DAT_803dca54 + 0x50))(0x4c,0,0,0);
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        FUN_8000a518(0xd8,1);
      }
    }
    else {
      iVar6 = FUN_80296554(uVar3,4);
      if (iVar6 == 0) {
        FUN_80009a94(3);
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
      *(undefined *)(iVar7 + 0x24) = 5;
      FUN_800200e8(0xae6,0);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(iVar7 + 0x24) = 0;
    *(uint *)(iVar7 + 0x18) = *(uint *)(iVar7 + 0x18) & 0xfffffffe;
    param_1[3] = param_1[3] & 0xbfff;
    FUN_800200e8(299,0);
    FUN_800200e8(0xae4,0);
    FUN_800200e8(0xae5,0);
    FUN_800200e8(0xae6,0);
  }
  else if (bVar1 < 5) {
    *(undefined *)(iVar7 + 0x24) = 5;
    FUN_800200e8(0xae6,0);
    FUN_800200e8(0xae4,1);
  }
  return;
}

