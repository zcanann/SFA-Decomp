// Function: FUN_80036d60
// Entry: 80036d60
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x80036e38) */

void FUN_80036d60(undefined4 param_1,undefined4 param_2,float *param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  longlong lVar10;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  lVar10 = FUN_802860d8();
  iVar3 = (int)((ulonglong)lVar10 >> 0x20);
  iVar5 = 0;
  if ((lVar10 < 0) || (0x53ffffffff < lVar10)) {
    iVar5 = 0;
  }
  else {
    fVar2 = FLOAT_803de968;
    if (param_3 != (float *)0x0) {
      fVar2 = *param_3 * *param_3;
    }
    dVar9 = (double)fVar2;
    uVar4 = (uint)(byte)(&DAT_80342cf8)[iVar3];
    bVar1 = (&DAT_80342cf9)[iVar3];
    piVar6 = &DAT_803428f8 + uVar4;
    for (; (int)uVar4 < (int)(uint)bVar1; uVar4 = uVar4 + 1) {
      if ((*piVar6 != (int)lVar10) &&
         (dVar8 = (double)FUN_800216d0((int)lVar10 + 0x18,*piVar6 + 0x18), dVar8 < dVar9)) {
        iVar5 = *piVar6;
        dVar9 = dVar8;
      }
      piVar6 = piVar6 + 1;
    }
    if ((iVar5 != 0) && (param_3 != (float *)0x0)) {
      dVar9 = (double)FUN_802931a0(dVar9);
      *param_3 = (float)dVar9;
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286124(iVar5);
  return;
}

