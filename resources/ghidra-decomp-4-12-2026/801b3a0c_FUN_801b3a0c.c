// Function: FUN_801b3a0c
// Entry: 801b3a0c
// Size: 280 bytes

uint FUN_801b3a0c(uint param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 2) == '\0') {
    uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x20));
    if (uVar1 != 0) {
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
      iVar2 = FUN_80036974(param_1,local_18,(int *)0x0,(uint *)0x0);
      if ((iVar2 != 0) && (*(short *)(local_18[0] + 0x46) == 0x18d)) {
        *(undefined *)(iVar3 + 2) = 2;
        FUN_8000bb38(param_1,0x2c1);
        iVar2 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
        iVar2 = FUN_8005b068(iVar2);
        if (iVar2 != 0) {
          FUN_801b38f8(iVar2,1,(uint)*(byte *)(iVar3 + 1));
          FUN_801b38f8(iVar2,0,*(byte *)(iVar3 + 1) + 1);
        }
      }
    }
  }
  else if (*(char *)(param_3 + 0x80) == '\x01') {
    FUN_800201ac((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e),1);
    *(undefined *)(iVar3 + 2) = 1;
  }
  uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 2));
  return uVar1 >> 5;
}

