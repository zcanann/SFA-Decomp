// Function: FUN_801d2b70
// Entry: 801d2b70
// Size: 228 bytes

void FUN_801d2b70(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002b9ac();
  if (iVar1 != 0) {
    FUN_80138ef8();
  }
  FUN_8000bb18(param_1,0xa3);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 0x40
  ;
  FUN_8009ab70((double)FLOAT_803e5378,param_1,0,1,1,1,0,1,0);
  *(undefined *)(param_3 + 0x14) = 1;
  *(byte *)(param_3 + 0x15) = *(byte *)(param_3 + 0x15) | 2;
  iVar1 = (int)*(short *)(iVar2 + 0x1c);
  if (iVar1 == -1) {
    iVar1 = 0;
    do {
      FUN_801d29e4(param_1,param_3);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  else {
    FUN_800200e8(iVar1,0);
  }
  return;
}

