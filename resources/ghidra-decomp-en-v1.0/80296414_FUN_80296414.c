// Function: FUN_80296414
// Entry: 80296414
// Size: 52 bytes

undefined4 FUN_80296414(int param_1,int param_2,undefined *param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *param_3 = *(undefined *)(iVar2 + 0x682);
  uVar1 = 0;
  if ((*(short *)(iVar2 + 0x274) == 0x1c) && (*(int *)(iVar2 + 0x67c) == param_2)) {
    uVar1 = 1;
  }
  return uVar1;
}

