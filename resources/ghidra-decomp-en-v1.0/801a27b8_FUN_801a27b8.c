// Function: FUN_801a27b8
// Entry: 801a27b8
// Size: 280 bytes

undefined4 FUN_801a27b8(int param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  iVar1 = FUN_8005aeec();
  if ((iVar1 == 0) || ((*(ushort *)(iVar1 + 4) & 8) == 0)) {
    uVar2 = 0;
  }
  else {
    for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar7 = iVar7 + 1) {
      iVar5 = FUN_800606ec(iVar1,iVar7);
      uVar3 = FUN_80060678();
      if (param_2 == uVar3) {
        *(uint *)(iVar5 + 0x10) = *(uint *)(iVar5 + 0x10) | 3;
      }
    }
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar7 = iVar7 + 1) {
      iVar4 = FUN_8006070c(iVar1,iVar7);
      iVar5 = iVar4;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar4 + 0x41); iVar6 = iVar6 + 1) {
        if (*(byte *)(iVar5 + 0x29) == param_2) {
          *(uint *)(iVar4 + 0x3c) = *(uint *)(iVar4 + 0x3c) | 2;
        }
        iVar5 = iVar5 + 8;
      }
    }
    uVar2 = 1;
  }
  return uVar2;
}

