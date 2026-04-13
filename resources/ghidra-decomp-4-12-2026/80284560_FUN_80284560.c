// Function: FUN_80284560
// Entry: 80284560
// Size: 148 bytes

/* WARNING: Removing unreachable block (ram,0x802845a0) */

void FUN_80284560(int *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(uint *)(*param_1 + 4) >> 0x18;
  uVar2 = *(uint *)(*param_1 + 4) & 0xffffff;
  if (uVar1 != 3) {
    if (uVar1 < 3) {
      if (1 < uVar1) {
        uVar2 = uVar2 << 1;
        goto LAB_802845d4;
      }
    }
    else if (5 < uVar1) goto LAB_802845d4;
    uVar1 = (uVar2 + 0xd) / 7;
    uVar2 = ((uVar2 + 0xd) - uVar1 >> 1) + uVar1 & 0xfffffff8;
  }
LAB_802845d4:
  uVar1 = FUN_80284bcc(*param_2,uVar2);
  *param_2 = uVar1;
  return;
}

