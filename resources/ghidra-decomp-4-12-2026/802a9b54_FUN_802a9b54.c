// Function: FUN_802a9b54
// Entry: 802a9b54
// Size: 740 bytes

void FUN_802a9b54(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)

{
  int iVar1;
  undefined2 *puVar2;
  int *piVar3;
  int iVar4;
  double dVar5;
  undefined8 uVar6;
  float local_18 [3];
  
  iVar4 = *(int *)(param_9 + 0xb8);
  local_18[0] = FLOAT_803e8d64;
  *(float *)(param_9 + 8) = FLOAT_803e8b78;
  dVar5 = FUN_8000fc54();
  FUN_80096c20(dVar5);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) & 0xefff;
  *(undefined *)(param_9 + 0x36) = 0xff;
  *(byte *)(iVar4 + 0x3f2) = *(byte *)(iVar4 + 0x3f2) & 0x7f;
  if ((*(byte *)(iVar4 + 0x3f2) >> 6 & 1) != 0) {
    *(float *)(iVar4 + 0x87c) = FLOAT_803e8c54;
  }
  *(byte *)(iVar4 + 0x3f2) = *(byte *)(iVar4 + 0x3f2) & 0xbf;
  *(byte *)(iVar4 + 0x3f2) = *(byte *)(iVar4 + 0x3f2) & 0xdf;
  *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0x7f;
  FUN_80036018(param_9);
  *(float *)(param_9 + 0x28) = FLOAT_803e8b3c;
  if ((*(ushort *)(param_11 + 0x6e) & 1) != 0) {
    FUN_802abd04(param_9,iVar4,7);
  }
  FUN_80026cf4(DAT_803df0a0,1);
  *(undefined *)(iVar4 + 0x8c4) = 2;
  if (DAT_803df0c4 != 0) {
    iVar1 = FUN_80036f50(0x20,param_9,local_18);
    if (iVar1 != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x24))();
    }
    uVar6 = FUN_80037da8(param_9,DAT_803df0c4);
    FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803df0c4);
    DAT_803df0c4 = 0;
  }
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
  *(undefined4 *)(iVar4 + 0x684) = 0;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xef;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xf7;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xfb;
  *(undefined *)(iVar4 + 0x40d) = 0;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0x7f;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xbf;
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xdf;
  *(undefined2 *)(iVar4 + 0x80a) = 0xffff;
  *(byte *)(iVar4 + 0x3f6) = *(byte *)(iVar4 + 0x3f6) & 0xbf;
  FUN_8017082c();
  *(byte *)(iVar4 + 0x3f0) = *(byte *)(iVar4 + 0x3f0) & 0xfd;
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
  FUN_80035f9c(param_9);
  *(float *)(iVar4 + 0x838) = FLOAT_803e8b3c;
  *(float *)(iVar4 + 0x83c) = FLOAT_803e8d68;
  *(float *)(iVar4 + 0x880) = FLOAT_803e8c3c;
  *(undefined *)(iVar4 + 0x25f) = 1;
  *(uint *)(iVar4 + 4) = *(uint *)(iVar4 + 4) & 0xffefffff;
  *(uint *)(iVar4 + 4) = *(uint *)(iVar4 + 4) | 0x8000000;
  if (**(char **)(*(int *)(param_9 + 0xb8) + 0x35c) < '\x01') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar4,3);
    *(undefined4 *)(iVar4 + 0x304) = 0;
  }
  puVar2 = (undefined2 *)FUN_800396d0(param_9,1);
  if (puVar2 != (undefined2 *)0x0) {
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
  }
  piVar3 = (int *)FUN_8002b660(param_9);
  FUN_80027b7c(piVar3);
  iVar4 = FUN_800395a4(param_9,1);
  *(undefined2 *)(iVar4 + 8) = 0;
  *(undefined2 *)(iVar4 + 10) = 0;
  iVar4 = FUN_800395a4(param_9,0);
  *(undefined2 *)(iVar4 + 8) = 0;
  *(undefined2 *)(iVar4 + 10) = 0;
  return;
}

