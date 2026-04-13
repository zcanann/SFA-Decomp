// Function: FUN_8026d6dc
// Entry: 8026d6dc
// Size: 232 bytes

void FUN_8026d6dc(uint param_1)

{
  uint uVar1;
  uint *puVar2;
  int *piVar3;
  
  piVar3 = (int *)(DAT_803dee98 + (param_1 & 0xff) * 0x38 + 0x14e8);
  if (*piVar3 != 0) {
    while ((puVar2 = (uint *)piVar3[1], *puVar2 != 0xffffffff &&
           (*puVar2 <= (uint)piVar3[(uint)*(byte *)(piVar3 + 0xc) * 2 + 9]))) {
      if ((*(uint *)(*(int *)(DAT_803dee98 + 0x118) + 0x10) & 0x40000000) == 0) {
        FUN_8026fca0(puVar2[1],(byte)DAT_803deea0,param_1);
        piVar3[2] = *(int *)(piVar3[1] + 4) << 10;
      }
      else {
        uVar1 = puVar2[1];
        piVar3[2] = uVar1;
        FUN_8026fca0(uVar1 >> 10,(byte)DAT_803deea0,param_1);
      }
      piVar3[1] = piVar3[1] + 8;
    }
  }
  return;
}

