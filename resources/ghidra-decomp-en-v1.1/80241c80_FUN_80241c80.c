// Function: FUN_80241c80
// Entry: 80241c80
// Size: 124 bytes

void FUN_80241c80(int param_1,int param_2)

{
  undefined4 uVar1;
  uint *puVar2;
  int iVar3;
  
  puVar2 = (uint *)(param_2 + -0x20);
  iVar3 = DAT_803dea90 + param_1 * 0xc;
  uVar1 = *(undefined4 *)(iVar3 + 8);
  if (*(uint **)(param_2 + -0x1c) != (uint *)0x0) {
    **(uint **)(param_2 + -0x1c) = *puVar2;
  }
  if (*puVar2 == 0) {
    uVar1 = *(undefined4 *)(param_2 + -0x1c);
  }
  else {
    *(undefined4 *)(*puVar2 + 4) = *(undefined4 *)(param_2 + -0x1c);
  }
  *(undefined4 *)(iVar3 + 8) = uVar1;
  puVar2 = FUN_80241ad8(*(uint **)(iVar3 + 4),puVar2);
  *(uint **)(iVar3 + 4) = puVar2;
  return;
}

