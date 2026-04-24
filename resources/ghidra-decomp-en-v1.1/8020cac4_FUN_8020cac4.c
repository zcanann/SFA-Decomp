// Function: FUN_8020cac4
// Entry: 8020cac4
// Size: 408 bytes

void FUN_8020cac4(int param_1)

{
  uint uVar1;
  undefined2 *puVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  FUN_80022264(0xffff8001,0x7fff);
  dVar4 = (double)FUN_80293994();
  if ((double)FLOAT_803e7278 <= dVar4) {
    dVar4 = (double)FUN_80293994();
  }
  else {
    dVar4 = (double)FUN_80293994();
    dVar4 = -dVar4;
  }
  FUN_80022264(0,(int)((double)FLOAT_803e7280 * dVar4 + (double)FLOAT_803e727c));
  dVar4 = (double)FUN_80293994();
  if ((double)FLOAT_803e7278 <= dVar4) {
    dVar4 = (double)FUN_80293994();
  }
  else {
    dVar4 = (double)FUN_80293994();
    dVar4 = -dVar4;
  }
  dVar3 = (double)FLOAT_803e7284;
  uVar1 = FUN_80022264(0xfffffed4,300);
  *puVar2 = (short)uVar1;
  uVar1 = FUN_80022264(0xfffffed4,300);
  puVar2[1] = (short)uVar1;
  uVar1 = FUN_80022264(0xfffffed4,300);
  puVar2[2] = (short)uVar1;
  uVar1 = FUN_80022264(0xffff8001,0x7fff);
  puVar2[3] = (short)uVar1;
  dVar5 = (double)FUN_80293994();
  puVar2[4] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                            (int)(dVar3 * dVar4) ^ 0x80000000) -
                                          DOUBLE_803e7270) * dVar5 + (double)FLOAT_803e7288);
  dVar5 = (double)FUN_80293eac();
  puVar2[5] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                            (int)(dVar3 * dVar4) ^ 0x80000000) -
                                          DOUBLE_803e7270) * dVar5);
  return;
}

