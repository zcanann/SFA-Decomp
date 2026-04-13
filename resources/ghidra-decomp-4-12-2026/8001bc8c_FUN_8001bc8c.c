// Function: FUN_8001bc8c
// Entry: 8001bc8c
// Size: 220 bytes

void FUN_8001bc8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  bool bVar1;
  int iVar2;
  short *psVar3;
  uint local_18;
  uint local_14 [4];
  
  iVar2 = FUN_80015da8(param_9,local_14,&local_18);
  if (iVar2 != 0) {
    if (DAT_803dd680 == 0) {
      psVar3 = &DAT_802caa68;
      iVar2 = 0xb;
      do {
        if (param_9 == (int)*psVar3) {
          bVar1 = true;
          goto LAB_8001bcf0;
        }
        psVar3 = psVar3 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      bVar1 = false;
LAB_8001bcf0:
      if (!bVar1) {
        return;
      }
    }
    DAT_803dd67c = local_14[0];
    DAT_803dd678 = local_18;
    if (local_18 != 0x29) {
      DAT_803dc040 = FUN_80019c28();
      FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd678);
    }
    else {
      FUN_8001a458(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    DAT_803dd670 = (uint)(local_18 == 0x29);
    DAT_803dd684 = 1;
    DAT_803dd677 = 0xff;
    DAT_803dd676 = 0xff;
    DAT_803dd675 = 0xff;
    DAT_803dd674 = 0xff;
  }
  return;
}

