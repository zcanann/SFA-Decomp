// Function: FUN_8022414c
// Entry: 8022414c
// Size: 192 bytes

undefined4 FUN_8022414c(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(byte *)(iVar3 + 0xac0) = *(byte *)(iVar3 + 0xac0) & 0xfe;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
  }
  iVar1 = FUN_80010340((double)FLOAT_803e79a0,(float *)(iVar3 + 0x9b0));
  if ((iVar1 != 0) || (*(int *)(iVar3 + 0x9c0) != 0)) {
    (**(code **)(*DAT_803dd71c + 0x90))((float *)(iVar3 + 0x9b0));
  }
  if (FLOAT_803e79a4 <= *(float *)(iVar3 + 0xab8)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 3;
  }
  return uVar2;
}

