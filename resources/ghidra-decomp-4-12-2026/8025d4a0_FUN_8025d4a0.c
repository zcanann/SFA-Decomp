// Function: FUN_8025d4a0
// Entry: 8025d4a0
// Size: 200 bytes

void FUN_8025d4a0(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  undefined *puVar3;
  
  puVar3 = &DAT_803b0000;
  piVar2 = (int *)FUN_80256f74();
  if (*(int *)(DAT_803dd210 + 0x4f4) != 0) {
    FUN_80258f60(piVar2,DAT_803dd210,(uint)puVar3);
  }
  if (*(char *)(DAT_803dd210 + 0x4f1) != '\0') {
    puVar3 = (undefined *)0x4f8;
    FUN_80003494(0x803af944,DAT_803dd210,0x4f8);
  }
  uVar1 = DAT_803dd210;
  DAT_803af924 = param_1 + param_2 + -4;
  DAT_803af93c = 0;
  DAT_803af920 = param_1;
  DAT_803af928 = param_2;
  DAT_803af934 = param_1;
  DAT_803af938 = param_1;
  *(undefined *)(DAT_803dd210 + 0x4f0) = 1;
  FUN_802569cc(piVar2,uVar1,(uint)puVar3);
  DAT_803ded70 = piVar2;
  FUN_80256744((uint *)&DAT_803af920);
  return;
}

