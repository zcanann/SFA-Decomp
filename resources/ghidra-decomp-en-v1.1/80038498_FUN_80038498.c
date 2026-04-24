// Function: FUN_80038498
// Entry: 80038498
// Size: 140 bytes

void FUN_80038498(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)FUN_8002b660(param_1);
  iVar2 = (int)*(char *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2 * 0x18 +
                         (int)*(char *)(param_1 + 0xad) + 0x12);
  if ((iVar2 < 0) || ((int)(uint)*(byte *)(*piVar1 + 0xf3) <= iVar2)) {
    FUN_80028630(piVar1,0);
  }
  else {
    FUN_80028630(piVar1,iVar2);
  }
  return;
}

