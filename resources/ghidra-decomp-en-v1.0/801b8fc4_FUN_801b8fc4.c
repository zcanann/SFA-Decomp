// Function: FUN_801b8fc4
// Entry: 801b8fc4
// Size: 576 bytes

void FUN_801b8fc4(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(iVar4 + 0x9c) == 0) || ((*(ushort *)(*(int *)(iVar4 + 0x9c) + 0xb0) & 0x40) == 0)) {
    if (*(char *)(iVar4 + 0xb8) == '\0') {
      uVar1 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * 4;
      if (0xff < uVar1) {
        uVar1 = 0xff;
      }
      *(char *)(param_1 + 0x36) = (char)uVar1;
      if ((*(byte *)(iVar4 + 0xb6) & 1) == 0) {
        uVar2 = FUN_8002e0b4(*(undefined4 *)(iVar4 + 0xa0));
        *(undefined4 *)(iVar4 + 0x9c) = uVar2;
        uVar2 = (**(code **)(**(int **)(*(int *)(iVar4 + 0x9c) + 0x68) + 0x20))
                          (*(int *)(iVar4 + 0x9c),iVar4 + 0x84,iVar4 + 0x88,iVar4 + 0x8c,0);
        *(undefined4 *)(iVar4 + 0x90) = uVar2;
        *(undefined4 *)(iVar4 + 0x80) = 0;
        *(code **)(iVar4 + 0x94) = FUN_80010dc0;
        *(undefined **)(iVar4 + 0x98) = &LAB_80010d54;
        FUN_80010a6c(iVar4);
        *(byte *)(iVar4 + 0xb6) = *(byte *)(iVar4 + 0xb6) | 1;
      }
      FUN_80010320((double)*(float *)(iVar4 + 0xa4),iVar4);
      uVar3 = *(uint *)(iVar4 + 0x10);
      uVar1 = *(int *)(iVar4 + 0x90) - 4;
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar4 + 0x68);
      if (-1 < *(char *)(iVar4 + 0xb9)) {
        *(float *)(param_1 + 0x10) = FLOAT_803e4b34 + *(float *)(iVar4 + 0x6c);
      }
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar4 + 0x70);
      if (((int)uVar3 >> 0x1f) + ((uint)(uVar1 <= uVar3) - ((int)uVar1 >> 0x1f)) != 0) {
        *(byte *)(iVar4 + 0xb9) = *(byte *)(iVar4 + 0xb9) & 0x7f | 0x80;
      }
      *(short *)(iVar4 + 0xb4) =
           (short)(int)(FLOAT_803db414 * *(float *)(iVar4 + 0xac) +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0xb4)) -
                              DOUBLE_803e4b40));
      if (*(char *)(iVar4 + 0xb9) < '\0') {
        *(float *)(param_1 + 0x10) = -(FLOAT_803e4b38 * FLOAT_803db414 - *(float *)(param_1 + 0x10))
        ;
        if (*(float *)(param_1 + 0x10) < *(float *)(iVar4 + 0x6c)) {
          FUN_80035f00(param_1);
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x100;
          uVar2 = FUN_8002b9ec();
          FUN_80296d20(uVar2,param_1);
        }
        if (*(float *)(param_1 + 0x10) < *(float *)(iVar4 + 0x6c) - FLOAT_803e4b3c) {
          FUN_8002cbc4(param_1);
        }
      }
    }
  }
  else {
    *(byte *)(iVar4 + 0xb6) = *(byte *)(iVar4 + 0xb6) & 0xfe;
    *(undefined4 *)(iVar4 + 0x9c) = 0;
  }
  return;
}

