// Function: FUN_80028384
// Entry: 80028384
// Size: 100 bytes

void FUN_80028384(int *param_1,int param_2,undefined4 *param_3)

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
  iVar1 = param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + param_2 * 0x40;
  *param_3 = *(undefined4 *)(iVar1 + 0xc);
  param_3[1] = *(undefined4 *)(iVar1 + 0x1c);
  param_3[2] = *(undefined4 *)(iVar1 + 0x2c);
  return;
}

