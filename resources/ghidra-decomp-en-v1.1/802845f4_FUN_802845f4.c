// Function: FUN_802845f4
// Entry: 802845f4
// Size: 132 bytes

/* WARNING: Removing unreachable block (ram,0x80284628) */

void FUN_802845f4(int param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(param_1 + 4) >> 0x18;
  uVar2 = *(uint *)(param_1 + 4) & 0xffffff;
  if (uVar1 != 3) {
    if (uVar1 < 3) {
      if (1 < uVar1) {
        uVar2 = uVar2 << 1;
        goto LAB_8028465c;
      }
    }
    else if (5 < uVar1) goto LAB_8028465c;
    uVar1 = (uVar2 + 0xd) / 7;
    uVar2 = ((uVar2 + 0xd) - uVar1 >> 1) + uVar1 & 0xfffffff8;
  }
LAB_8028465c:
  FUN_80284cbc(param_2,uVar2);
  return;
}

