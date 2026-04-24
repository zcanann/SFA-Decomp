// Function: FUN_8029e240
// Entry: 8029e240
// Size: 144 bytes

void FUN_8029e240(int param_1,uint *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *param_2 = *param_2 & 0xffffbfff;
  cVar1 = *(char *)(iVar2 + 0x8c8);
  if (((cVar1 != 'H') && (cVar1 != 'G')) && (iVar2 = FUN_80080490(), iVar2 == 0)) {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
  }
  FUN_80035f9c(param_1);
  return;
}

