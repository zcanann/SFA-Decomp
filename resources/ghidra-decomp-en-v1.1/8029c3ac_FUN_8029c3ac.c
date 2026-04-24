// Function: FUN_8029c3ac
// Entry: 8029c3ac
// Size: 360 bytes

/* WARNING: Removing unreachable block (ram,0x8029c4f0) */
/* WARNING: Removing unreachable block (ram,0x8029c3bc) */

undefined4
FUN_8029c3ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    if (DAT_803df0d9 == 0) {
      DAT_803df0d9 = 1;
    }
    else if (2 < DAT_803df0d9) {
      DAT_803df0d9 = 2;
    }
    *(undefined4 *)(param_10 + 0x2a0) = *(undefined4 *)((uint)DAT_803df0d9 * 4 + -0x7fc22d0c);
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(&FLOAT_803dd2ec)[DAT_803df0d9],0,param_12,param_13,param_14,param_15,
                 param_16);
    DAT_803df0d9 = 0;
  }
  if (*(char *)(param_10 + 0x346) == '\0') {
    (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
    uVar1 = 0;
  }
  else {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    if (*(int *)(param_10 + 0x2d0) == 0) {
      *(byte *)(iVar2 + 0x3f1) = *(byte *)(iVar2 + 0x3f1) & 0x7f | 0x80;
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      uVar1 = 2;
    }
    else {
      *(code **)(param_10 + 0x308) = FUN_8029d028;
      uVar1 = 0x25;
    }
  }
  return uVar1;
}

