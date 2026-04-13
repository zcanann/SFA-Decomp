// Function: FUN_801c54d4
// Entry: 801c54d4
// Size: 952 bytes

/* WARNING: Removing unreachable block (ram,0x801c5610) */

void FUN_801c54d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_8002bac4();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar7 = FUN_80088f20(7,'\x01');
    uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20d,0,in_r7,in_r8,in_r9,in_r10);
    uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20e,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3,0x222,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
  }
  iVar4 = FUN_8004832c(0x20);
  FUN_80043604(iVar4,1,0);
  FUN_801c4c18(param_9);
  FUN_801d84c4(iVar6 + 0x18,8,-1,-1,0xae6,(int *)0xa);
  FUN_801d8650(iVar6 + 0x18,4,-1,-1,0xcbb,(int *)0x8);
  FUN_801d84c4(iVar6 + 0x18,0x10,-1,-1,0xcbb,(int *)0xc4);
  bVar1 = *(byte *)(iVar6 + 0x24);
  if (bVar1 == 3) {
    (**(code **)(*DAT_803dd6d4 + 0x4c))((int)(short)param_9[0x5a]);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    *(undefined *)(iVar6 + 0x24) = 4;
    FUN_800201ac(0xae6,0);
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if ((*(uint *)(iVar6 + 0x18) & 1) != 0) {
        param_9[3] = param_9[3] | 0x4000;
        *param_9 = 0;
        *(undefined *)(iVar6 + 0x24) = 2;
        *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
        FUN_800201ac(0xae6,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      }
    }
    else if (bVar1 == 0) {
      fVar2 = *(float *)(iVar6 + 0x14) - FLOAT_803dc074;
      *(float *)(iVar6 + 0x14) = fVar2;
      if (fVar2 <= FLOAT_803e5bd8) {
        FUN_8000bb38((uint)param_9,0x343);
        uVar5 = FUN_80022264(500,1000);
        *(float *)(iVar6 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e5bd0);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar6 + 0x24) = 1;
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x4c,0,0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_8000a538((int *)0xd8,1);
      }
    }
    else {
      uVar5 = FUN_80296cb4(iVar3,4);
      if (uVar5 == 0) {
        FUN_80009a94(3);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      *(undefined *)(iVar6 + 0x24) = 5;
      FUN_800201ac(0xae6,0);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(iVar6 + 0x24) = 0;
    *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
    param_9[3] = param_9[3] & 0xbfff;
    FUN_800201ac(299,0);
    FUN_800201ac(0xae4,0);
    FUN_800201ac(0xae5,0);
    FUN_800201ac(0xae6,0);
  }
  else if (bVar1 < 5) {
    *(undefined *)(iVar6 + 0x24) = 5;
    FUN_800201ac(0xae6,0);
    FUN_800201ac(0xae4,1);
  }
  return;
}

