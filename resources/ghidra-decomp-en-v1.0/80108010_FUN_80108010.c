// Function: FUN_80108010
// Entry: 80108010
// Size: 388 bytes

void FUN_80108010(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  float local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (*(short *)(param_1 + 0x44) != 1) {
    *(undefined4 *)(DAT_803dd548 + 0x120) = *(undefined4 *)(param_1 + 0x18);
    *(float *)(DAT_803dd548 + 0x124) = FLOAT_803e17c0 + *(float *)(param_1 + 0x1c);
    *(undefined4 *)(DAT_803dd548 + 0x128) = *(undefined4 *)(param_1 + 0x20);
    *(undefined4 *)(DAT_803dd548 + 0x130) = *(undefined4 *)(DAT_803dd548 + 0x124);
    goto LAB_801080e0;
  }
  FUN_80296bd4(param_1,&local_28,&local_24,&local_20);
  if (param_2 == 0) {
    if ((*(float *)(DAT_803dd548 + 0x120) != local_28) ||
       (*(float *)(DAT_803dd548 + 0x128) != local_20)) goto LAB_80108074;
  }
  else {
LAB_80108074:
    *(undefined4 *)(DAT_803dd548 + 0x130) = local_24;
  }
  *(float *)(DAT_803dd548 + 0x120) = local_28;
  *(undefined4 *)(DAT_803dd548 + 0x124) = local_24;
  *(float *)(DAT_803dd548 + 0x128) = local_20;
LAB_801080e0:
  iVar1 = FUN_801e1da8();
  if ((iVar1 != 0) && (iVar2 = FUN_801e12dc(), iVar2 == 2)) {
    local_1c = *(float *)(param_1 + 0x18) - *(float *)(iVar1 + 0x18);
    local_18 = (FLOAT_803e17c0 + *(float *)(param_1 + 0x1c)) - *(float *)(iVar1 + 0x1c);
    local_14 = *(float *)(param_1 + 0x20) - *(float *)(iVar1 + 0x20);
    FUN_80021ac8(iVar1,&local_1c);
    *(float *)(DAT_803dd548 + 0x120) = *(float *)(iVar1 + 0x18) + local_1c;
    *(float *)(DAT_803dd548 + 0x124) = *(float *)(iVar1 + 0x1c) + local_18;
    *(float *)(DAT_803dd548 + 0x128) = *(float *)(iVar1 + 0x20) + local_14;
  }
  return;
}

