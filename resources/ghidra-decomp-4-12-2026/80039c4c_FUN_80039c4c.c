// Function: FUN_80039c4c
// Entry: 80039c4c
// Size: 676 bytes

void FUN_80039c4c(double param_1,undefined4 param_2,char *param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  
  bVar3 = (double)FLOAT_803df664 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar3) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
    *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
    param_3[0x14] = '\0';
    param_3[0x15] = '\0';
    param_3[0x1c] = '\0';
    param_3[0x1d] = '\0';
  }
  switch(*(ushort *)(param_3 + 0x1a) & 0xff) {
  case 0:
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
    uVar2 = FUN_80022264(0x32,200);
    *(short *)(param_3 + 0x1c) = (short)uVar2;
    break;
  case 1:
    *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    if ((*(short *)(param_3 + 0x1c) < 0) && (uVar2 = FUN_80022264(0,100), 0x5a < (int)uVar2)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 5;
      if (*param_3 == '\0') {
        param_3[0x14] = '\x1f';
        param_3[0x15] = -1;
        uVar2 = FUN_80022264(0,1);
        if (uVar2 == 0) {
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
      }
      else {
        uVar2 = FUN_80022264(0,100);
        if (0 < (int)uVar2) {
          param_3[0x14] = '\x1f';
          param_3[0x15] = -1;
          uVar2 = FUN_80022264(0,1);
          if (uVar2 == 0) {
            *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
          }
        }
      }
    }
    break;
  case 4:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039ab8((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
        *(undefined2 *)(param_4 + 2) = 0;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
    break;
  case 5:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039ab8((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 6;
        *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        uVar2 = FUN_80022264(0x14,100);
        *(short *)(param_3 + 0x1c) = (short)uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
    break;
  case 6:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_80039ab8((int)param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
        param_3[0x14] = '\0';
        param_3[0x15] = '\0';
        uVar2 = FUN_80022264(0x14,100);
        *(short *)(param_3 + 0x1c) = (short)uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
    }
  }
  return;
}

