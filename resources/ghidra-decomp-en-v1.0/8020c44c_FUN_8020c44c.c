// Function: FUN_8020c44c
// Entry: 8020c44c
// Size: 408 bytes

void FUN_8020c44c(int param_1)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 *puVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  puVar3 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_800221a0(0xffff8001,0x7fff);
  dVar5 = (double)FUN_80293234(uVar1);
  if ((double)FLOAT_803e65e0 <= dVar5) {
    dVar5 = (double)FUN_80293234(uVar1);
  }
  else {
    dVar5 = (double)FUN_80293234(uVar1);
    dVar5 = -dVar5;
  }
  FUN_800221a0(0,(int)((double)FLOAT_803e65e8 * dVar5 + (double)FLOAT_803e65e4));
  dVar5 = (double)FUN_80293234(uVar1);
  if ((double)FLOAT_803e65e0 <= dVar5) {
    dVar5 = (double)FUN_80293234(uVar1);
  }
  else {
    dVar5 = (double)FUN_80293234(uVar1);
    dVar5 = -dVar5;
  }
  dVar4 = (double)FLOAT_803e65ec;
  uVar2 = FUN_800221a0(0xfffffed4,300);
  *puVar3 = uVar2;
  uVar2 = FUN_800221a0(0xfffffed4,300);
  puVar3[1] = uVar2;
  uVar2 = FUN_800221a0(0xfffffed4,300);
  puVar3[2] = uVar2;
  uVar2 = FUN_800221a0(0xffff8001,0x7fff);
  puVar3[3] = uVar2;
  dVar6 = (double)FUN_80293234(uVar1);
  puVar3[4] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                            (int)(dVar4 * dVar5) ^ 0x80000000) -
                                          DOUBLE_803e65d8) * dVar6 + (double)FLOAT_803e65f0);
  dVar6 = (double)FUN_8029374c(uVar1);
  puVar3[5] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                            (int)(dVar4 * dVar5) ^ 0x80000000) -
                                          DOUBLE_803e65d8) * dVar6);
  return;
}

