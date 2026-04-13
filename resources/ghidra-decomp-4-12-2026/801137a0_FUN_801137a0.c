// Function: FUN_801137a0
// Entry: 801137a0
// Size: 824 bytes

/* WARNING: Removing unreachable block (ram,0x80113ab8) */
/* WARNING: Removing unreachable block (ram,0x80113ab0) */
/* WARNING: Removing unreachable block (ram,0x80113aa8) */
/* WARNING: Removing unreachable block (ram,0x801137c0) */
/* WARNING: Removing unreachable block (ram,0x801137b8) */
/* WARNING: Removing unreachable block (ram,0x801137b0) */

void FUN_801137a0(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined2 param_6)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar5 = (int)uVar12;
  *(undefined4 *)(param_3 + 0x318) = 0;
  *(undefined4 *)(param_3 + 0x31c) = 0;
  *(undefined2 *)(param_3 + 0x330) = 0;
  fVar1 = FLOAT_803e28ac;
  *(float *)(param_3 + 0x290) = FLOAT_803e28ac;
  *(float *)(param_3 + 0x28c) = fVar1;
  if (*(char *)(iVar5 + 0x56) != '\x01') {
    *(undefined4 *)(iVar5 + 0x40) = *(undefined4 *)(psVar3 + 6);
    *(undefined4 *)(iVar5 + 0x44) = *(undefined4 *)(psVar3 + 8);
    *(undefined4 *)(iVar5 + 0x48) = *(undefined4 *)(psVar3 + 10);
    FLOAT_803de250 = FLOAT_803e28f0;
    DAT_803de254 = '\0';
  }
  *(undefined2 *)(iVar5 + 0x6e) = 0;
  *(undefined *)(iVar5 + 0x56) = 1;
  fVar1 = *(float *)(iVar5 + 0x40) - *(float *)(psVar3 + 6);
  fVar2 = *(float *)(iVar5 + 0x48) - *(float *)(psVar3 + 10);
  dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    dVar11 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar5 + 0x40));
    dVar10 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(iVar5 + 0x48));
    dVar8 = FUN_80293900((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10)));
    dVar9 = (double)(FLOAT_803dc074 * (float)(dVar8 - dVar7) * FLOAT_803e28f4);
    dVar6 = (double)FLOAT_803e28ec;
    if ((dVar9 <= dVar6) && (dVar6 = dVar9, dVar9 < (double)FLOAT_803e28dc)) {
      dVar6 = (double)FLOAT_803e28dc;
    }
    if (dVar7 <= (double)FLOAT_803de250) {
      DAT_803de254 = DAT_803de254 + '\x01';
    }
    if ((dVar8 <= dVar7) || ('\t' < DAT_803de254)) {
      iVar4 = (int)*psVar3 - (uint)**(ushort **)(param_3 + 0x2d0);
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
      *psVar3 = *psVar3 - (short)((int)(iVar4 * (uint)DAT_803dc070) >> 3);
      if ('\n' < DAT_803de254) {
        iVar4 = 0;
      }
      if ((iVar4 < 0x100) && (-0x100 < iVar4)) {
        *(undefined *)(iVar5 + 0x56) = 0;
        *(short *)(iVar5 + 0x5a) = *(short *)(iVar5 + 0x58) + -1;
      }
      else {
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)FLOAT_803dc074,(double)FLOAT_803dc074,psVar3,param_3,param_4,param_5);
      }
    }
    else {
      *(float *)(param_3 + 0x290) = (float)(-(double)(float)(dVar11 / dVar8) * dVar6);
      *(float *)(param_3 + 0x28c) = (float)((double)(float)(dVar10 / dVar8) * dVar6);
      *(float *)(psVar3 + 6) =
           (float)(dVar7 * (double)(float)(dVar11 / dVar8) + (double)*(float *)(iVar5 + 0x40));
      *(float *)(psVar3 + 10) =
           (float)(dVar7 * (double)(float)(dVar10 / dVar8) + (double)*(float *)(iVar5 + 0x48));
      (**(code **)(*DAT_803dd70c + 8))
                ((double)FLOAT_803dc074,(double)FLOAT_803dc074,psVar3,param_3,param_4,param_5);
    }
    FLOAT_803de250 = (float)dVar7;
    if (*(char *)(iVar5 + 0x56) == '\0') {
      *(undefined *)(param_3 + 0x405) = 0;
      *(undefined2 *)(param_3 + 0x274) = param_6;
      *(undefined4 *)(param_3 + 0x2d0) = 0;
      *(undefined2 *)(iVar5 + 0x6e) = 0xffff;
      *(ushort *)(iVar5 + 0x6e) = *(ushort *)(iVar5 + 0x6e) & 0xffbf;
      *(undefined *)(param_3 + 0x25f) = 0;
      FUN_800201ac((int)*(short *)(param_3 + 0x3f4),0);
    }
  }
  FUN_80286888();
  return;
}

