// Function: FUN_8029dae0
// Entry: 8029dae0
// Size: 144 bytes

void FUN_8029dae0(int param_1,uint *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *param_2 = *param_2 & 0xffffbfff;
  cVar1 = *(char *)(iVar2 + 0x8c8);
  if (((cVar1 != 'H') && (cVar1 != 'G')) && (iVar2 = FUN_80080204(), iVar2 == 0)) {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
  }
  FUN_80035ea4(param_1);
  return;
}

