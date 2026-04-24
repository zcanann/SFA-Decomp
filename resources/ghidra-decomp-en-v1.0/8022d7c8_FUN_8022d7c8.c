// Function: FUN_8022d7c8
// Entry: 8022d7c8
// Size: 320 bytes

void FUN_8022d7c8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  short unaff_r29;
  short unaff_r30;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d0();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (*(char *)(iVar2 + 0x338) != '\0') {
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e6efc *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(ushort *)(iVar2 + 0x33c))
                                                 - DOUBLE_803e6ee8)) / FLOAT_803e6f00));
    dVar3 = (double)FLOAT_803e6ff4;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e6efc *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(ushort *)(iVar2 + 0x33a))
                                                 - DOUBLE_803e6ee8)) / FLOAT_803e6f00));
    dVar4 = (double)FLOAT_803e6f5c;
    unaff_r30 = (short)(int)(dVar3 * dVar5);
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) + unaff_r30;
    unaff_r29 = (short)(int)(dVar4 * dVar6);
    *(short *)(iVar1 + 4) = *(short *)(iVar1 + 4) + unaff_r29;
  }
  FUN_8003b8f4((double)FLOAT_803e6ed0,iVar1,(int)uVar7,param_3,param_4,param_5);
  if (*(char *)(iVar2 + 0x338) != '\0') {
    *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) - unaff_r30;
    *(short *)(iVar1 + 4) = *(short *)(iVar1 + 4) - unaff_r29;
  }
  FUN_8028611c();
  return;
}

