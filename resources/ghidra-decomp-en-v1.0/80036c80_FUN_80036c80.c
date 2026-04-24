// Function: FUN_80036c80
// Entry: 80036c80
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x80036d40) */

void FUN_80036c80(undefined4 param_1,undefined4 param_2,float *param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  longlong lVar9;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  lVar9 = FUN_802860d8();
  iVar2 = (int)((ulonglong)lVar9 >> 0x20);
  iVar4 = 0;
  dVar8 = (double)(*param_3 * *param_3);
  if ((lVar9 < 0) || (0x53ffffffff < lVar9)) {
    iVar4 = 0;
  }
  else {
    uVar3 = (uint)(byte)(&DAT_80342cf8)[iVar2];
    bVar1 = (&DAT_80342cf9)[iVar2];
    piVar5 = &DAT_803428f8 + uVar3;
    while ((int)uVar3 < (int)(uint)bVar1) {
      if (*piVar5 != 0) {
        dVar7 = (double)FUN_8024795c((int)lVar9,*piVar5 + 0x18);
        if (dVar7 < dVar8) {
          iVar4 = *piVar5;
          dVar8 = dVar7;
        }
        piVar5 = piVar5 + 1;
        uVar3 = uVar3 + 1;
      }
    }
    if (iVar4 != 0) {
      dVar8 = (double)FUN_802931a0(dVar8);
      *param_3 = (float)dVar8;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286124(iVar4);
  return;
}

