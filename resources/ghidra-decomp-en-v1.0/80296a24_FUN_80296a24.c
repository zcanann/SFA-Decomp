// Function: FUN_80296a24
// Entry: 80296a24
// Size: 104 bytes

void FUN_80296a24(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
  iVar2 = *(short *)(iVar1 + 4) + param_2;
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (*(short *)(iVar1 + 6) < iVar2) {
    iVar2 = (int)*(short *)(iVar1 + 6);
  }
  *(short *)(iVar1 + 4) = (short)iVar2;
  if (0 < param_2) {
    FUN_8000bb18(0,0x21c);
  }
  return;
}

