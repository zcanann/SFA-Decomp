// Function: FUN_8027a660
// Entry: 8027a660
// Size: 628 bytes

/* WARNING: Removing unreachable block (ram,0x8027a778) */
/* WARNING: Removing unreachable block (ram,0x8027a69c) */
/* WARNING: Removing unreachable block (ram,0x8027a67c) */

undefined4 FUN_8027a660(char *param_1)

{
  byte bVar1;
  int iVar2;
  
  if (*param_1 != '\x01') {
    if (*param_1 != '\0') {
      return 0;
    }
    bVar1 = param_1[1];
    if (bVar1 != 2) {
      if (1 < bVar1) {
        if (bVar1 != 4) {
          return 0;
        }
        goto LAB_8027a74c;
      }
      if ((bVar1 == 0) &&
         (*(int *)(param_1 + 4) = *(int *)(param_1 + 0x14), *(int *)(param_1 + 0x14) != 0)) {
        param_1[1] = '\x01';
        *(undefined4 *)(param_1 + 8) = 0;
        *(uint *)(param_1 + 0x10) = 0x7fff0000 / *(uint *)(param_1 + 0x14);
        return 0;
      }
      *(int *)(param_1 + 4) = *(int *)(param_1 + 0x18);
      if (*(int *)(param_1 + 0x18) != 0) {
        param_1[1] = '\x02';
        *(undefined4 *)(param_1 + 8) = 0x7fff0000;
        *(uint *)(param_1 + 0x10) =
             -(((uint)*(ushort *)(param_1 + 0x1c) * -0x10000 + 0x7fff0000) /
              *(uint *)(param_1 + 0x18));
        return 0;
      }
    }
    if (*(short *)(param_1 + 0x1c) != 0) {
      param_1[1] = '\x03';
      *(uint *)(param_1 + 8) = (uint)*(ushort *)(param_1 + 0x1c) << 0x10;
      *(undefined4 *)(param_1 + 0x10) = 0;
      return 0;
    }
LAB_8027a74c:
    *(undefined4 *)(param_1 + 8) = 0;
    return 1;
  }
  bVar1 = param_1[1];
  if (bVar1 != 2) {
    if (1 < bVar1) {
      if (bVar1 != 4) {
        return 0;
      }
      goto LAB_8027a8c0;
    }
    if ((bVar1 == 0) &&
       (*(int *)(param_1 + 4) = *(int *)(param_1 + 0x14), *(int *)(param_1 + 0x14) != 0)) {
      param_1[1] = '\x01';
      if (param_1[0x26] == '\0') {
        *(undefined4 *)(param_1 + 8) = 0;
        *(uint *)(param_1 + 0x10) = 0x7fff0000 / *(uint *)(param_1 + 4);
        return 0;
      }
      *(undefined4 *)(param_1 + 0xc) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      *(uint *)(param_1 + 0x10) = 0xc10000 / *(uint *)(param_1 + 4);
      return 0;
    }
    *(uint *)(param_1 + 4) =
         *(int *)(param_1 + 0x18) * (((0xc1 - (uint)*(ushort *)(param_1 + 0x1c)) * 0x10000) / 0xc1)
         >> 0x10;
    if (*(int *)(param_1 + 4) != 0) {
      param_1[1] = '\x02';
      *(undefined4 *)(param_1 + 8) = 0x7fff0000;
      *(undefined4 *)(param_1 + 0xc) = 0xc10000;
      *(uint *)(param_1 + 0x10) =
           -(((0xc1 - (uint)*(ushort *)(param_1 + 0x1c)) * 0x10000) / *(uint *)(param_1 + 4));
      return 0;
    }
  }
  if (*(short *)(param_1 + 0x1c) != 0) {
    param_1[1] = '\x03';
    *(uint *)(param_1 + 0xc) = (uint)*(ushort *)(param_1 + 0x1c) << 0x10;
    iVar2 = 0xc1 - (*(int *)(param_1 + 0xc) + 0x8000 >> 0x10);
    if (iVar2 < 0) {
      iVar2 = 0;
    }
    *(uint *)(param_1 + 8) = (uint)(ushort)(&DAT_8032f618)[iVar2] << 0x10;
    *(undefined4 *)(param_1 + 0x10) = 0;
    return 0;
  }
LAB_8027a8c0:
  *(undefined4 *)(param_1 + 8) = 0;
  return 1;
}

