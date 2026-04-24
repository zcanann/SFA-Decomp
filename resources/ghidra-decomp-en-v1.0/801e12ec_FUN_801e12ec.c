// Function: FUN_801e12ec
// Entry: 801e12ec
// Size: 636 bytes

/* WARNING: Removing unreachable block (ram,0x801e1548) */

void FUN_801e12ec(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f31;
  double local_38;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(param_1 + 0xf4) = 7;
  iVar1 = FUN_8001ffb4(0x9f);
  if (((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xa0), iVar1 == 0)) &&
     (iVar1 = FUN_8001ffb4(0x91c), iVar1 != 0)) {
    DAT_803ddc2c = '\x01';
    FUN_800200e8(0xa0,1);
    (**(code **)(*DAT_803dca4c + 8))(10,1);
  }
  FUN_801e108c(iVar2);
  if ((DAT_803ddc2c != '\0') && (iVar1 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar1 != 0)) {
    (**(code **)(*DAT_803dca4c + 0xc))(0x50,1);
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    *(undefined *)(iVar2 + 0x70) = 3;
    DAT_803ddc2c = '\0';
  }
  (**(code **)(*DAT_803dca64 + 0x28))((double)FLOAT_803e57c8,(double)FLOAT_803e56cc);
  (**(code **)(*DAT_803dca64 + 0x20))(0);
  local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x68));
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e56e4 * (float)(local_38 - DOUBLE_803e57e8)) /
                                       FLOAT_803e56e8));
  if (*(char *)(iVar2 + 0x81) == '\0') {
    if ((double)FLOAT_803e57cc <= dVar4) {
      if ((double)FLOAT_803e57d0 < dVar4) {
        iVar1 = FUN_8001ffb4(0xa71);
        if (iVar1 == 0) {
          FUN_8000bb18(param_1,0x145);
        }
        *(undefined *)(iVar2 + 0x81) = 1;
      }
    }
    else {
      iVar1 = FUN_8001ffb4(0xa71);
      if (iVar1 == 0) {
        FUN_8000bb18(param_1,0x144);
      }
      *(undefined *)(iVar2 + 0x81) = 1;
    }
  }
  else if (((double)FLOAT_803e57d4 < dVar4) && (dVar4 < (double)FLOAT_803e57d8)) {
    *(undefined *)(iVar2 + 0x81) = 0;
  }
  *(short *)(param_1 + 4) = (short)(int)((double)FLOAT_803e57dc * dVar4);
  *(short *)(iVar2 + 0x68) =
       (short)(int)(FLOAT_803e57e0 * FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x68)) -
                          DOUBLE_803e57e8));
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

