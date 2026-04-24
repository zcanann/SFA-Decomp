// Function: FUN_801ce430
// Entry: 801ce430
// Size: 280 bytes

undefined4 FUN_801ce430(short *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar1 + 0x43c) & 0x20) == 0) {
    FUN_8000b7dc((int)param_1,0x7f);
    *(float *)(iVar1 + 0x54) = FLOAT_803e5ea4;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) & 0xef;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) | 0x20;
  }
  if ((*(byte *)(iVar1 + 0x43c) & 4) != 0) {
    *(float *)(iVar1 + 0x18) = FLOAT_803e5ea4;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfff7;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    FUN_801ce548(param_1,iVar1,1);
  }
  FUN_8006f0b4((double)FLOAT_803e5ea8,(double)FLOAT_803e5ea8,param_1,iVar1 + 0x440,8,iVar1 + 0x45c,
               iVar1 + 0x16c);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    param_1[0x58] = param_1[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 4;
  }
  return 0;
}

