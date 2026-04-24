// Function: FUN_8029bc4c
// Entry: 8029bc4c
// Size: 360 bytes

/* WARNING: Removing unreachable block (ram,0x8029bd90) */

undefined4 FUN_8029bc4c(undefined8 param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = *(int *)(param_2 + 0xb8);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    if (DAT_803de459 == 0) {
      DAT_803de459 = 1;
    }
    else if (2 < DAT_803de459) {
      DAT_803de459 = 2;
    }
    *(undefined4 *)(param_3 + 0x2a0) = *(undefined4 *)((uint)DAT_803de459 * 4 + -0x7fc23974);
    FUN_80030334((double)FLOAT_803e7ea4,param_2,(&FLOAT_803dc684)[DAT_803de459],0);
    DAT_803de459 = 0;
  }
  if (*(char *)(param_3 + 0x346) == '\0') {
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
    uVar1 = 0;
  }
  else {
    *(undefined *)(*(int *)(param_2 + 0x54) + 0x70) = 0;
    if (*(int *)(param_3 + 0x2d0) == 0) {
      *(byte *)(iVar2 + 0x3f1) = *(byte *)(iVar2 + 0x3f1) & 0x7f | 0x80;
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_3 + 0x308) = FUN_802a514c;
      uVar1 = 2;
    }
    else {
      *(code **)(param_3 + 0x308) = FUN_8029c8c8;
      uVar1 = 0x25;
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return uVar1;
}

