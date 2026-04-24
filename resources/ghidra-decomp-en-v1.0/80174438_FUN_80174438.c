// Function: FUN_80174438
// Entry: 80174438
// Size: 336 bytes

undefined4 FUN_80174438(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_8002b9ec();
  if (((*(ushort *)(param_2 + 0x100) & 0x80) == 0) && (iVar2 = FUN_80295a04(uVar1,10), iVar2 == 0))
  {
    FUN_8000bb18(param_1,0x66);
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 2;
    if ((*(ushort *)(param_2 + 0x100) & 4) == 0) {
      FUN_80174bfc(param_1,param_2);
    }
    if (*(float *)(param_1 + 0xc) <= FLOAT_803e352c + *(float *)(iVar3 + 8)) {
      FUN_800200e8((int)*(short *)(param_2 + 0xac),1);
      *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
      *(float *)(param_1 + 0xc) = (float)((double)*(float *)(iVar3 + 8) - DOUBLE_803e3530);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(float *)(param_1 + 0x14) = (float)(DOUBLE_803e3538 + (double)*(float *)(iVar3 + 0x10));
      FUN_8000bb18(param_1,0x68);
    }
    iVar2 = FUN_8001ffb4(0xa1a);
    if (iVar2 != 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
    }
  }
  else {
    FUN_8000b7bc(param_1,8);
  }
  return 0;
}

