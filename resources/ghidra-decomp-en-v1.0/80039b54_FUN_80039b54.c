// Function: FUN_80039b54
// Entry: 80039b54
// Size: 676 bytes

void FUN_80039b54(double param_1,undefined4 param_2,char *param_3,int param_4)

{
  int iVar1;
  undefined2 uVar2;
  bool bVar3;
  
  bVar3 = (double)FLOAT_803de9e4 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar3) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
    *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
    *(undefined2 *)(param_3 + 0x14) = 0;
    *(undefined2 *)(param_3 + 0x1c) = 0;
  }
  switch(*(ushort *)(param_3 + 0x1a) & 0xff) {
  case 0:
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
    uVar2 = FUN_800221a0(0x32,200);
    *(undefined2 *)(param_3 + 0x1c) = uVar2;
    break;
  case 1:
    *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803db410;
    if ((*(short *)(param_3 + 0x1c) < 0) && (iVar1 = FUN_800221a0(0,100), 0x5a < iVar1)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 5;
      if (*param_3 == '\0') {
        *(undefined2 *)(param_3 + 0x14) = 0x1fff;
        iVar1 = FUN_800221a0(0,1);
        if (iVar1 == 0) {
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
      }
      else {
        iVar1 = FUN_800221a0(0,100);
        if (0 < iVar1) {
          *(undefined2 *)(param_3 + 0x14) = 0x1fff;
          iVar1 = FUN_800221a0(0,1);
          if (iVar1 == 0) {
            *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
          }
        }
      }
    }
    break;
  case 4:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_800399c0(param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8;
        *(undefined2 *)(param_4 + 2) = 0;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803db410;
    }
    break;
  case 5:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_800399c0(param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 6;
        *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        uVar2 = FUN_800221a0(0x14,100);
        *(undefined2 *)(param_3 + 0x1c) = uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803db410;
    }
    break;
  case 6:
    if (*(short *)(param_3 + 0x1c) < 1) {
      iVar1 = FUN_800399c0(param_3,param_4);
      if (iVar1 != 0) {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar3 << 8 | 4;
        *(undefined2 *)(param_3 + 0x14) = 0;
        uVar2 = FUN_800221a0(0x14,100);
        *(undefined2 *)(param_3 + 0x1c) = uVar2;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803db410;
    }
  }
  return;
}

