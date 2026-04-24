// Function: FUN_80113504
// Entry: 80113504
// Size: 824 bytes

/* WARNING: Removing unreachable block (ram,0x80113814) */
/* WARNING: Removing unreachable block (ram,0x8011380c) */
/* WARNING: Removing unreachable block (ram,0x8011381c) */

void FUN_80113504(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined2 param_6)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  undefined8 uVar14;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar14 = FUN_802860d8();
  psVar3 = (short *)((ulonglong)uVar14 >> 0x20);
  iVar6 = (int)uVar14;
  *(undefined4 *)(param_3 + 0x318) = 0;
  *(undefined4 *)(param_3 + 0x31c) = 0;
  *(undefined2 *)(param_3 + 0x330) = 0;
  fVar1 = FLOAT_803e1c2c;
  *(float *)(param_3 + 0x290) = FLOAT_803e1c2c;
  *(float *)(param_3 + 0x28c) = fVar1;
  if (*(char *)(iVar6 + 0x56) != '\x01') {
    *(undefined4 *)(iVar6 + 0x40) = *(undefined4 *)(psVar3 + 6);
    *(undefined4 *)(iVar6 + 0x44) = *(undefined4 *)(psVar3 + 8);
    *(undefined4 *)(iVar6 + 0x48) = *(undefined4 *)(psVar3 + 10);
    FLOAT_803dd5d8 = FLOAT_803e1c70;
    DAT_803dd5dc = '\0';
  }
  *(undefined2 *)(iVar6 + 0x6e) = 0;
  *(undefined *)(iVar6 + 0x56) = 1;
  fVar1 = *(float *)(iVar6 + 0x40) - *(float *)(psVar3 + 6);
  fVar2 = *(float *)(iVar6 + 0x48) - *(float *)(psVar3 + 10);
  dVar9 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 == 0) {
    uVar5 = 0;
  }
  else {
    dVar13 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar6 + 0x40));
    dVar12 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(iVar6 + 0x48));
    dVar10 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12)
                                                 ));
    dVar11 = (double)(FLOAT_803db414 * (float)(dVar10 - dVar9) * FLOAT_803e1c74);
    dVar8 = (double)FLOAT_803e1c6c;
    if ((dVar11 <= dVar8) && (dVar8 = dVar11, dVar11 < (double)FLOAT_803e1c5c)) {
      dVar8 = (double)FLOAT_803e1c5c;
    }
    if (dVar9 <= (double)FLOAT_803dd5d8) {
      DAT_803dd5dc = DAT_803dd5dc + '\x01';
    }
    if ((dVar10 <= dVar9) || ('\t' < DAT_803dd5dc)) {
      iVar4 = (int)*psVar3 - ((int)**(short **)(param_3 + 0x2d0) & 0xffffU);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      if (0x2000 < iVar4) {
        iVar4 = 0x2000;
      }
      if (iVar4 < -0x2000) {
        iVar4 = -0x2000;
      }
      *psVar3 = *psVar3 - (short)((int)(iVar4 * (uint)DAT_803db410) >> 3);
      if ('\n' < DAT_803dd5dc) {
        iVar4 = 0;
      }
      if ((iVar4 < 0x100) && (-0x100 < iVar4)) {
        *(undefined *)(iVar6 + 0x56) = 0;
        *(short *)(iVar6 + 0x5a) = *(short *)(iVar6 + 0x58) + -1;
      }
      else {
        (**(code **)(*DAT_803dca8c + 8))
                  ((double)FLOAT_803db414,(double)FLOAT_803db414,psVar3,param_3,param_4,param_5);
      }
    }
    else {
      *(float *)(param_3 + 0x290) = (float)(-(double)(float)(dVar13 / dVar10) * dVar8);
      *(float *)(param_3 + 0x28c) = (float)((double)(float)(dVar12 / dVar10) * dVar8);
      *(float *)(psVar3 + 6) =
           (float)(dVar9 * (double)(float)(dVar13 / dVar10) + (double)*(float *)(iVar6 + 0x40));
      *(float *)(psVar3 + 10) =
           (float)(dVar9 * (double)(float)(dVar12 / dVar10) + (double)*(float *)(iVar6 + 0x48));
      (**(code **)(*DAT_803dca8c + 8))
                ((double)FLOAT_803db414,(double)FLOAT_803db414,psVar3,param_3,param_4,param_5);
    }
    FLOAT_803dd5d8 = (float)dVar9;
    if (*(char *)(iVar6 + 0x56) == '\0') {
      *(undefined *)(param_3 + 0x405) = 0;
      *(undefined2 *)(param_3 + 0x274) = param_6;
      *(undefined4 *)(param_3 + 0x2d0) = 0;
      *(undefined2 *)(iVar6 + 0x6e) = 0xffff;
      *(ushort *)(iVar6 + 0x6e) = *(ushort *)(iVar6 + 0x6e) & 0xffbf;
      *(undefined *)(param_3 + 0x25f) = 0;
      FUN_800200e8((int)*(short *)(param_3 + 0x3f4),0);
    }
    uVar5 = 1;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286124(uVar5);
  return;
}

