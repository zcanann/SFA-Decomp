// Function: FUN_80283dfc
// Entry: 80283dfc
// Size: 148 bytes

/* WARNING: Removing unreachable block (ram,0x80283e3c) */

void FUN_80283dfc(int *param_1,undefined4 *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  
  uVar1 = *(uint *)(*param_1 + 4) >> 0x18;
  uVar3 = *(uint *)(*param_1 + 4) & 0xffffff;
  if (uVar1 != 3) {
    if (uVar1 < 3) {
      if (1 < uVar1) {
        uVar3 = uVar3 << 1;
        goto LAB_80283e70;
      }
    }
    else if (5 < uVar1) goto LAB_80283e70;
    uVar1 = (uVar3 + 0xd) / 7;
    uVar3 = ((uVar3 + 0xd) - uVar1 >> 1) + uVar1 & 0xfffffff8;
  }
LAB_80283e70:
  uVar2 = FUN_80284468(*param_2,uVar3);
  *param_2 = uVar2;
  return;
}

