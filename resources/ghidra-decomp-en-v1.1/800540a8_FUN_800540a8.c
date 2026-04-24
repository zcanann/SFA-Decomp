// Function: FUN_800540a8
// Entry: 800540a8
// Size: 632 bytes

void FUN_800540a8(int param_1,uint *param_2,int *param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  uVar1 = *param_2;
  uVar3 = uVar1 & 0x80000;
  if ((uVar1 & 0x20000) == 0) {
    if ((uVar1 & 0x40000) == 0) {
      if (uVar3 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
        while ((int)(uint)*(ushort *)(param_1 + 0x10) <= *param_3) {
          *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x10);
        }
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
        while (*param_3 < 0) {
          *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x10);
        }
      }
    }
    else {
      if (uVar3 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
      }
      do {
        iVar2 = *param_3;
        if (iVar2 < 0) {
          *param_3 = -iVar2;
          *param_2 = *param_2 & 0xfff7ffff;
        }
        iVar4 = *param_3;
        uVar3 = (uint)*(ushort *)(param_1 + 0x10);
        if ((int)uVar3 <= iVar4) {
          *param_3 = (uVar3 * 2 + -1) - iVar4;
          *param_2 = *param_2 | 0x80000;
        }
      } while ((int)uVar3 <= iVar4 || iVar2 < 0);
    }
  }
  else if ((uVar1 & 0x40000) == 0) {
    uVar3 = FUN_80022264(0,1000);
    if (0x3d9 < (int)uVar3) {
      *param_2 = *param_2 & 0xfff7ffff;
      *param_2 = *param_2 | 0x40000;
    }
  }
  else if (uVar3 == 0) {
    *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
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
    *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
    if (*param_3 < 0) {
      *param_3 = 0;
      *param_2 = *param_2 & 0xfff3ffff;
    }
  }
  return;
}

