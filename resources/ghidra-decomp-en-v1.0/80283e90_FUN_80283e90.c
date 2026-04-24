// Function: FUN_80283e90
// Entry: 80283e90
// Size: 132 bytes

/* WARNING: Removing unreachable block (ram,0x80283ec4) */

void FUN_80283e90(int param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(param_1 + 4) >> 0x18;
  uVar2 = *(uint *)(param_1 + 4) & 0xffffff;
  if (uVar1 != 3) {
    if (uVar1 < 3) {
      if (1 < uVar1) {
        uVar2 = uVar2 << 1;
        goto LAB_80283ef8;
      }
    }
    else if (5 < uVar1) goto LAB_80283ef8;
    uVar1 = (uVar2 + 0xd) / 7;
    uVar2 = ((uVar2 + 0xd) - uVar1 >> 1) + uVar1 & 0xfffffff8;
  }
LAB_80283ef8:
  FUN_80284558(param_2,uVar2);
  return;
}

