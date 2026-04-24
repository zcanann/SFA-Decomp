// Function: FUN_802a93f4
// Entry: 802a93f4
// Size: 740 bytes

void FUN_802a93f4(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined2 *puVar2;
  int iVar3;
  float local_18 [3];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e80cc;
  *(float *)(param_1 + 8) = FLOAT_803e7ee0;
  FUN_8000fc34();
  FUN_80096994();
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) & 0xefff;
  *(undefined *)(param_1 + 0x36) = 0xff;
  *(byte *)(iVar3 + 0x3f2) = *(byte *)(iVar3 + 0x3f2) & 0x7f;
  if ((*(byte *)(iVar3 + 0x3f2) >> 6 & 1) != 0) {
    *(float *)(iVar3 + 0x87c) = FLOAT_803e7fbc;
  }
  *(byte *)(iVar3 + 0x3f2) = *(byte *)(iVar3 + 0x3f2) & 0xbf;
  *(byte *)(iVar3 + 0x3f2) = *(byte *)(iVar3 + 0x3f2) & 0xdf;
  *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0x7f;
  FUN_80035f20(param_1);
  *(float *)(param_1 + 0x28) = FLOAT_803e7ea4;
  if ((*(ushort *)(param_3 + 0x6e) & 1) != 0) {
    FUN_802ab5a4(param_1,iVar3,7);
  }
  FUN_80026c30(DAT_803de420,1);
  *(undefined *)(iVar3 + 0x8c4) = 2;
  if (DAT_803de444 != 0) {
    iVar1 = FUN_80036e58(0x20,param_1,local_18);
    if (iVar1 != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x24))();
    }
    FUN_80037cb0(param_1,DAT_803de444);
    FUN_8002cbc4(DAT_803de444);
    DAT_803de444 = 0;
  }
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
  *(undefined4 *)(iVar3 + 0x684) = 0;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xef;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xf7;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xfb;
  *(undefined *)(iVar3 + 0x40d) = 0;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0x7f;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xbf;
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xdf;
  *(undefined2 *)(iVar3 + 0x80a) = 0xffff;
  *(byte *)(iVar3 + 0x3f6) = *(byte *)(iVar3 + 0x3f6) & 0xbf;
  FUN_80170380(DAT_803de450,2);
  *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xfd;
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
  FUN_80035ea4(param_1);
  *(float *)(iVar3 + 0x838) = FLOAT_803e7ea4;
  *(float *)(iVar3 + 0x83c) = FLOAT_803e80d0;
  *(float *)(iVar3 + 0x880) = FLOAT_803e7fa4;
  *(undefined *)(iVar3 + 0x25f) = 1;
  *(uint *)(iVar3 + 4) = *(uint *)(iVar3 + 4) & 0xffefffff;
  *(uint *)(iVar3 + 4) = *(uint *)(iVar3 + 4) | 0x8000000;
  if (**(char **)(*(int *)(param_1 + 0xb8) + 0x35c) < '\x01') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar3,3);
    *(undefined4 *)(iVar3 + 0x304) = 0;
  }
  puVar2 = (undefined2 *)FUN_800395d8(param_1,1);
  if (puVar2 != (undefined2 *)0x0) {
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
  }
  FUN_8002b588(param_1);
  FUN_80027ab8();
  iVar3 = FUN_800394ac(param_1,1,0);
  *(undefined2 *)(iVar3 + 8) = 0;
  *(undefined2 *)(iVar3 + 10) = 0;
  iVar3 = FUN_800394ac(param_1,0,0);
  *(undefined2 *)(iVar3 + 8) = 0;
  *(undefined2 *)(iVar3 + 10) = 0;
  return;
}

