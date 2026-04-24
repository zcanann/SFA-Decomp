// Function: FUN_801d5d48
// Entry: 801d5d48
// Size: 324 bytes

undefined4 FUN_801d5d48(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x625) & 8) == 0) {
    FUN_8000b7bc(param_1,0x7f);
    *(undefined *)(iVar3 + 0x624) = 0;
    uVar1 = FUN_800221a0(1000,2000);
    *(float *)(iVar3 + 0x630) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5428);
    *(byte *)(iVar3 + 0x625) = *(byte *)(iVar3 + 0x625) & 0xfb;
    *(byte *)(iVar3 + 0x625) = *(byte *)(iVar3 + 0x625) | 0x18;
    *(undefined *)(iVar3 + 0x63f) = 0;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  if ((*(byte *)(iVar3 + 0x625) & 2) != 0) {
    iVar2 = FUN_80114bb0(param_1,param_3,iVar3,0,0);
    if (iVar2 != 0) {
      return 0;
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    FUN_8003b310(param_1,iVar3 + 0x8b0);
  }
  *(undefined *)(iVar3 + 0x89f) = 0;
  FUN_8006ef38((double)FLOAT_803e5448,(double)FLOAT_803e5448,param_1,param_3 + 0xf0,8,iVar3 + 0x8e0,
               iVar3 + 0x644);
  return 0;
}

