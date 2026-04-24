// Function: FUN_80028630
// Entry: 80028630
// Size: 76 bytes

int FUN_80028630(int *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = (uint)*(byte *)(*param_1 + 0xf3);
  if (uVar2 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = uVar2 + *(byte *)(*param_1 + 0xf4);
  }
  if (iVar1 <= param_2) {
    param_2 = 0;
  }
  return param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + param_2 * 0x40;
}

