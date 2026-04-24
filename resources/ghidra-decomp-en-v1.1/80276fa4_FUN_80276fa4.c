// Function: FUN_80276fa4
// Entry: 80276fa4
// Size: 356 bytes

/* WARNING: Removing unreachable block (ram,0x80277020) */

void FUN_80276fa4(int param_1,uint *param_2)

{
  uint uVar1;
  uint local_10 [2];
  
  *(char *)(param_1 + 0x131) = (char)(*param_2 >> 0x10);
  local_10[0] = param_2[1] >> 0x10;
  if ((param_2[1] >> 8 & 1) == 0) {
    FUN_802836f4(local_10,param_1);
  }
  else {
    FUN_802836e4((int *)local_10);
  }
  *(uint *)(param_1 + 0x134) = local_10[0];
  uVar1 = *param_2 >> 8 & 0xff;
  if (uVar1 == 1) {
    if (*(byte *)(param_1 + 0x121) != 0xff) {
      FUN_80281a9c(0x41,*(byte *)(param_1 + 0x121),*(byte *)(param_1 + 0x122),0x7f);
    }
  }
  else {
    if (uVar1 == 0) {
      if (*(byte *)(param_1 + 0x121) != 0xff) {
        FUN_80281a9c(0x41,*(byte *)(param_1 + 0x121),*(byte *)(param_1 + 0x122),0);
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffffbff;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
      return;
    }
    if (2 < uVar1) {
      return;
    }
    if (*(byte *)(param_1 + 0x121) == 0xff) {
      return;
    }
    uVar1 = FUN_80282288(0x41,(uint)*(byte *)(param_1 + 0x121),(uint)*(byte *)(param_1 + 0x122));
    if ((uVar1 & 0xffff) < 0x1f81) {
      return;
    }
  }
  if ((*(uint *)(param_1 + 0x118) & 0x400) == 0) {
    FUN_8026fd1c(param_1);
  }
  *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x400;
  return;
}

