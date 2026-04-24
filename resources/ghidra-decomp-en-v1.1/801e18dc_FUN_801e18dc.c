// Function: FUN_801e18dc
// Entry: 801e18dc
// Size: 636 bytes

/* WARNING: Removing unreachable block (ram,0x801e1b38) */
/* WARNING: Removing unreachable block (ram,0x801e18ec) */

void FUN_801e18dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined4 *)(param_9 + 0xf4) = 7;
  uVar1 = FUN_80020078(0x9f);
  if (((uVar1 != 0) && (uVar1 = FUN_80020078(0xa0), uVar1 == 0)) &&
     (uVar1 = FUN_80020078(0x91c), uVar1 != 0)) {
    DAT_803de8ac = '\x01';
    FUN_800201ac(0xa0,1);
    param_1 = (**(code **)(*DAT_803dd6cc + 8))(10,1);
  }
  FUN_801e167c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
  if ((DAT_803de8ac != '\0') && (iVar2 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar2 != 0)) {
    (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
    *(undefined *)(iVar3 + 0x70) = 3;
    DAT_803de8ac = '\0';
  }
  (**(code **)(*DAT_803dd6e4 + 0x28))((double)FLOAT_803e6460,(double)FLOAT_803e6364);
  (**(code **)(*DAT_803dd6e4 + 0x20))(0);
  dVar4 = (double)FUN_802945e0();
  if (*(char *)(iVar3 + 0x81) == '\0') {
    if ((double)FLOAT_803e6464 <= dVar4) {
      if ((double)FLOAT_803e6468 < dVar4) {
        uVar1 = FUN_80020078(0xa71);
        if (uVar1 == 0) {
          FUN_8000bb38(param_9,0x145);
        }
        *(undefined *)(iVar3 + 0x81) = 1;
      }
    }
    else {
      uVar1 = FUN_80020078(0xa71);
      if (uVar1 == 0) {
        FUN_8000bb38(param_9,0x144);
      }
      *(undefined *)(iVar3 + 0x81) = 1;
    }
  }
  else if (((double)FLOAT_803e646c < dVar4) && (dVar4 < (double)FLOAT_803e6470)) {
    *(undefined *)(iVar3 + 0x81) = 0;
  }
  *(short *)(param_9 + 4) = (short)(int)((double)FLOAT_803e6474 * dVar4);
  *(short *)(iVar3 + 0x68) =
       (short)(int)(FLOAT_803e6478 * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x68)) -
                          DOUBLE_803e6480));
  return;
}

