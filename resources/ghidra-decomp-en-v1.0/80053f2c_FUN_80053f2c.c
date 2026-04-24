// Function: FUN_80053f2c
// Entry: 80053f2c
// Size: 632 bytes

void FUN_80053f2c(int param_1,uint *param_2,int *param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = *param_2;
  uVar2 = uVar1 & 0x80000;
  if ((uVar1 & 0x20000) == 0) {
    if ((uVar1 & 0x40000) == 0) {
      if (uVar2 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
        while ((int)(uint)*(ushort *)(param_1 + 0x10) <= *param_3) {
          *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x10);
        }
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
        while (*param_3 < 0) {
          *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x10);
        }
      }
    }
    else {
      if (uVar2 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
      }
      do {
        iVar3 = *param_3;
        if (iVar3 < 0) {
          *param_3 = -iVar3;
          *param_2 = *param_2 & 0xfff7ffff;
        }
        iVar4 = *param_3;
        uVar2 = (uint)*(ushort *)(param_1 + 0x10);
        if ((int)uVar2 <= iVar4) {
          *param_3 = (uVar2 * 2 + -1) - iVar4;
          *param_2 = *param_2 | 0x80000;
        }
      } while ((int)uVar2 <= iVar4 || iVar3 < 0);
    }
  }
  else if ((uVar1 & 0x40000) == 0) {
    iVar3 = FUN_800221a0(0,1000);
    if (0x3d9 < iVar3) {
      *param_2 = *param_2 & 0xfff7ffff;
      *param_2 = *param_2 | 0x40000;
    }
  }
  else if (uVar2 == 0) {
    *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
    if ((int)(uint)*(ushort *)(param_1 + 0x10) <= *param_3) {
      *param_3 = ((uint)*(ushort *)(param_1 + 0x10) * 2 + -1) - *param_3;
      if (*param_3 < 0) {
        *param_3 = 0;
        *param_2 = *param_2 & 0xfff3ffff;
      }
      else {
        *param_2 = *param_2 | 0x80000;
      }
    }
  }
  else {
    *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803db410;
    if (*param_3 < 0) {
      *param_3 = 0;
      *param_2 = *param_2 & 0xfff3ffff;
    }
  }
  return;
}

