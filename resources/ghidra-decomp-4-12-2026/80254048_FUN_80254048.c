// Function: FUN_80254048
// Entry: 80254048
// Size: 124 bytes

int FUN_80254048(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = (int *)(&DAT_803af060 + param_1 * 0x40);
  FUN_80243e74();
  iVar1 = *piVar2;
  *piVar2 = param_2;
  if (param_1 == 2) {
    FUN_802538ec(0,(int *)&DAT_803af060);
  }
  else {
    FUN_802538ec(param_1,piVar2);
  }
  FUN_80243e9c();
  return iVar1;
}

