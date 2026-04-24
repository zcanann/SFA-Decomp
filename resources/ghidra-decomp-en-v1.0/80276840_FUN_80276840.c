// Function: FUN_80276840
// Entry: 80276840
// Size: 356 bytes

/* WARNING: Removing unreachable block (ram,0x802768bc) */

void FUN_80276840(int param_1,uint *param_2)

{
  uint uVar1;
  ushort uVar2;
  uint local_10 [2];
  
  *(char *)(param_1 + 0x131) = (char)(*param_2 >> 0x10);
  local_10[0] = param_2[1] >> 0x10;
  if ((param_2[1] >> 8 & 1) == 0) {
    FUN_80282f90(local_10,param_1);
  }
  else {
    FUN_80282f80(local_10);
  }
  *(uint *)(param_1 + 0x134) = local_10[0];
  uVar1 = *param_2 >> 8 & 0xff;
  if (uVar1 == 1) {
    if (*(char *)(param_1 + 0x121) != -1) {
      FUN_80281338(0x41,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),0x7f);
    }
  }
  else {
    if (uVar1 == 0) {
      if (*(char *)(param_1 + 0x121) != -1) {
        FUN_80281338(0x41,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),0);
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffffbff;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
      return;
    }
    if (2 < uVar1) {
      return;
    }
    if (*(char *)(param_1 + 0x121) == -1) {
      return;
    }
    uVar2 = FUN_80281b24(0x41,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122));
    if (uVar2 < 0x1f81) {
      return;
    }
  }
  if ((*(uint *)(param_1 + 0x118) & 0x400) == 0) {
    FUN_8026f5b8(param_1);
  }
  *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x400;
  return;
}

