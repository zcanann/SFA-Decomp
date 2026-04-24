// Function: FUN_801eca64
// Entry: 801eca64
// Size: 352 bytes

void FUN_801eca64(short *param_1)

{
  float fVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  iVar2 = FUN_8005b490(*(undefined4 *)
                        ((uint)*(byte *)(psVar3 + 0x21a) * 0xc + -0x7fcd7a70 +
                        (uint)*(byte *)((int)psVar3 + 0x435) * 4),0,0,0,0);
  if (iVar2 != 0) {
    if (*(char *)(psVar3 + 0x21a) != '\0') {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      *param_1 = (ushort)*(byte *)(iVar2 + 0x29) << 8;
    }
    (**(code **)(*DAT_803dca6c + 0x10))(param_1,psVar3 + 0x14,0);
    *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(param_1 + 10);
    *psVar3 = *param_1;
    fVar1 = FLOAT_803e5ae8;
    *(float *)(psVar3 + 0x24a) = FLOAT_803e5ae8;
    *(float *)(psVar3 + 0x24c) = fVar1;
    *(float *)(psVar3 + 0x24e) = fVar1;
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,psVar3 + 0xbc);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
    *(undefined *)((int)psVar3 + 0x3d3) = 1;
  }
  return;
}

