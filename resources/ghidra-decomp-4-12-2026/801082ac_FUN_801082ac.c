// Function: FUN_801082ac
// Entry: 801082ac
// Size: 388 bytes

void FUN_801082ac(int param_1,int param_2)

{
  ushort *puVar1;
  int iVar2;
  float local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (*(short *)(param_1 + 0x44) == 1) {
    FUN_80297334(param_1,&local_28,&local_24,&local_20);
    if (((param_2 != 0) || (*(float *)(DAT_803de1c0 + 0x120) != local_28)) ||
       (*(float *)(DAT_803de1c0 + 0x128) != local_20)) {
      *(undefined4 *)(DAT_803de1c0 + 0x130) = local_24;
    }
    *(float *)(DAT_803de1c0 + 0x120) = local_28;
    *(undefined4 *)(DAT_803de1c0 + 0x124) = local_24;
    *(float *)(DAT_803de1c0 + 0x128) = local_20;
  }
  else {
    *(undefined4 *)(DAT_803de1c0 + 0x120) = *(undefined4 *)(param_1 + 0x18);
    *(float *)(DAT_803de1c0 + 0x124) = FLOAT_803e2440 + *(float *)(param_1 + 0x1c);
    *(undefined4 *)(DAT_803de1c0 + 0x128) = *(undefined4 *)(param_1 + 0x20);
    *(undefined4 *)(DAT_803de1c0 + 0x130) = *(undefined4 *)(DAT_803de1c0 + 0x124);
  }
  puVar1 = (ushort *)FUN_801e2398();
  if ((puVar1 != (ushort *)0x0) && (iVar2 = FUN_801e18cc((int)puVar1), iVar2 == 2)) {
    local_1c = *(float *)(param_1 + 0x18) - *(float *)(puVar1 + 0xc);
    local_18 = (FLOAT_803e2440 + *(float *)(param_1 + 0x1c)) - *(float *)(puVar1 + 0xe);
    local_14 = *(float *)(param_1 + 0x20) - *(float *)(puVar1 + 0x10);
    FUN_80021b8c(puVar1,&local_1c);
    *(float *)(DAT_803de1c0 + 0x120) = *(float *)(puVar1 + 0xc) + local_1c;
    *(float *)(DAT_803de1c0 + 0x124) = *(float *)(puVar1 + 0xe) + local_18;
    *(float *)(DAT_803de1c0 + 0x128) = *(float *)(puVar1 + 0x10) + local_14;
  }
  return;
}

