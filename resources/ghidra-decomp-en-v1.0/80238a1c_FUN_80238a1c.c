// Function: FUN_80238a1c
// Entry: 80238a1c
// Size: 148 bytes

void FUN_80238a1c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8008016c(iVar1);
  *(undefined *)(iVar1 + 0xc) = *(undefined *)(param_2 + 0x19);
  *(float *)(iVar1 + 8) = FLOAT_803e7424;
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0x7f;
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0xbf;
  *(undefined4 *)(iVar1 + 4) = 0;
  FUN_80037200(param_1,0x4c);
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0xdf;
  return;
}

