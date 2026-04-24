// Function: FUN_8002856c
// Entry: 8002856c
// Size: 76 bytes

int FUN_8002856c(int *param_1,int param_2)

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

