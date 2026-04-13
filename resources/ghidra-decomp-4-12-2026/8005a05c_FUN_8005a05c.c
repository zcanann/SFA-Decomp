// Function: FUN_8005a05c
// Entry: 8005a05c
// Size: 556 bytes

void FUN_8005a05c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int local_28;
  int iStack_24;
  int local_20 [8];
  
  uVar8 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = iVar2 * 7;
  iVar3 = iVar2 * 0x1c;
  uVar6 = *(uint *)(DAT_803ddafc + iVar3);
  uVar5 = *(int *)(DAT_803ddafc + iVar3 + 0x1c) - uVar6;
  uVar7 = FUN_80048d20(uVar6,local_20,&iStack_24,&local_28,iVar4);
  DAT_803ddb20 = FUN_80023d8c(uVar5 + (local_20[0] + 7 >> 3) + 0x401 + local_28,5);
  uVar7 = FUN_800490c4(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1d,
                       DAT_803ddb20,uVar6,uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0xc) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 4)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x14) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 8)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x30) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0xc)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x2c) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x10)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x34) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x14)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x20) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x18)) - uVar6;
  FUN_800484a4(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               *(undefined4 *)(DAT_803ddafc + iVar3 + 0x18),iVar2,*(uint *)(DAT_803ddb20 + 0x20),
               uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0x10) =
       (local_28 + *(int *)(DAT_803ddafc + iVar3 + 0x1c) + DAT_803ddb20) - uVar6;
  for (iVar3 = 0; fVar1 = FLOAT_803df84c, iVar3 < (local_20[0] + 7 >> 3) + 1; iVar3 = iVar3 + 1) {
    *(undefined *)(*(int *)(DAT_803ddb20 + 0x10) + iVar3) = 0;
  }
  *(float *)(DAT_803ddb20 + 0x24) = FLOAT_803df84c;
  *(float *)(DAT_803ddb20 + 0x28) = fVar1;
  *(undefined *)(DAT_803ddb20 + 0x18) = 0;
  *(undefined *)(DAT_803ddb20 + 0x19) = 0;
  if ((int)uVar8 == 0) {
    FUN_800598a8();
    (**(code **)(*DAT_803dd72c + 0x58))(iVar2);
  }
  FUN_8028688c();
  return;
}

