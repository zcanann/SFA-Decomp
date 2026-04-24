// Function: FUN_80198de8
// Entry: 80198de8
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x80198f84) */

void FUN_80198de8(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  char cVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar19 = FUN_802860dc();
  iVar12 = (int)((ulonglong)uVar19 >> 0x20);
  iVar13 = *(int *)(iVar12 + 0x4c);
  iVar14 = *(int *)(iVar12 + 0xb8);
  fVar1 = *(float *)(iVar14 + 0x18);
  fVar2 = *(float *)(iVar14 + 0x14);
  fVar6 = fVar2 * *(float *)(iVar14 + 0x24);
  fVar3 = *(float *)(iVar14 + 0xc);
  fVar4 = *(float *)(iVar14 + 0x1c);
  fVar5 = *(float *)(iVar14 + 0x10);
  fVar7 = fVar5 * *(float *)(iVar14 + 0x20);
  dVar17 = (double)(fVar1 + fVar6 + fVar3 * fVar4 + fVar7);
  dVar18 = (double)(fVar1 + fVar2 * *(float *)(iVar14 + 0x30) +
                            fVar3 * *(float *)(iVar14 + 0x28) + fVar5 * *(float *)(iVar14 + 0x2c));
  dVar16 = (double)FLOAT_803e40d8;
  if (dVar16 <= dVar18) {
    if (dVar16 <= dVar17) {
      cVar11 = -2;
    }
    else {
      cVar11 = -1;
    }
  }
  else if (dVar16 <= dVar17) {
    cVar11 = '\x01';
  }
  else {
    cVar11 = '\x02';
  }
  if ((cVar11 == '\x01') || (cVar11 == -1)) {
    fVar9 = *(float *)(iVar14 + 0x28) - fVar4;
    fVar8 = *(float *)(iVar14 + 0x2c) - *(float *)(iVar14 + 0x20);
    fVar10 = *(float *)(iVar14 + 0x30) - *(float *)(iVar14 + 0x24);
    fVar1 = (((-fVar3 * fVar4 - fVar7) - fVar6) - fVar1) /
            (fVar2 * fVar10 + fVar3 * fVar9 + fVar5 * fVar8);
    local_48 = fVar1 * fVar9 + fVar4;
    local_44 = fVar1 * fVar8 + *(float *)(iVar14 + 0x20);
    local_40 = fVar1 * fVar10 + *(float *)(iVar14 + 0x24);
    FUN_80247494(iVar14 + 0x38,&local_48,&local_48);
    fVar1 = *(float *)(iVar14 + 0x34);
    if ((-fVar1 <= local_48) &&
       (((local_48 <= fVar1 && (-fVar1 <= local_44)) && (local_44 <= fVar1)))) {
      FUN_8007d6dc(s_____________TRIGGER__d_ident__d_80322518,(int)cVar11,
                   *(undefined4 *)(iVar13 + 0x14));
      local_38 = (longlong)(int)dVar18;
      FUN_801993b0(iVar12,(int)uVar19,(int)cVar11,(int)dVar18);
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  FUN_80286128();
  return;
}

