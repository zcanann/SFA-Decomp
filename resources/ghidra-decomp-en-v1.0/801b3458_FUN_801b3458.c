// Function: FUN_801b3458
// Entry: 801b3458
// Size: 280 bytes

uint FUN_801b3458(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 2) == '\0') {
    iVar2 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x20));
    if (iVar2 != 0) {
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
      iVar2 = FUN_8003687c(param_1,local_18,0,0);
      if ((iVar2 != 0) && (*(short *)(local_18[0] + 0x46) == 0x18d)) {
        *(undefined *)(iVar3 + 2) = 2;
        FUN_8000bb18(param_1,0x2c1);
        FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14));
        iVar2 = FUN_8005aeec();
        if (iVar2 != 0) {
          FUN_801b3344(iVar2,1,*(undefined *)(iVar3 + 1));
          FUN_801b3344(iVar2,0,*(byte *)(iVar3 + 1) + 1);
        }
      }
    }
  }
  else if (*(char *)(param_3 + 0x80) == '\x01') {
    FUN_800200e8((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e),1);
    *(undefined *)(iVar3 + 2) = 1;
  }
  uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 2));
  return uVar1 >> 5;
}

