// Function: FUN_80193844
// Entry: 80193844
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80193aa4) */
/* WARNING: Removing unreachable block (ram,0x80193a9c) */
/* WARNING: Removing unreachable block (ram,0x80193a94) */
/* WARNING: Removing unreachable block (ram,0x80193a8c) */
/* WARNING: Removing unreachable block (ram,0x8019386c) */
/* WARNING: Removing unreachable block (ram,0x80193864) */
/* WARNING: Removing unreachable block (ram,0x8019385c) */
/* WARNING: Removing unreachable block (ram,0x80193854) */

void FUN_80193844(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar18;
  double in_f31;
  double dVar19;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  float local_a8;
  float local_a4;
  float local_a0;
  longlong local_98;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined8 local_80;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar20 = FUN_8028681c();
  iVar8 = (int)((ulonglong)uVar20 >> 0x20);
  piVar6 = (int *)uVar20;
  iVar2 = FUN_8005b478((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10));
  iVar2 = FUN_8005b068(iVar2);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 4) & 8) != 0)) {
    dVar16 = (double)FUN_802925a0();
    local_98 = (longlong)(int)dVar16;
    dVar17 = (double)FUN_802925a0();
    local_90 = (longlong)(int)dVar17;
    uStack_84 = (int)dVar16 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar19 = (double)(*(float *)(iVar8 + 0xc) -
                     (FLOAT_803e4c58 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e4c60) +
                     FLOAT_803dda58));
    local_80 = (double)CONCAT44(0x43300000,(int)dVar17 ^ 0x80000000);
    dVar17 = (double)(*(float *)(iVar8 + 0x14) -
                     (FLOAT_803e4c58 * (float)(local_80 - DOUBLE_803e4c60) + FLOAT_803dda5c));
    iVar10 = 0;
    *(undefined *)((int)piVar6 + 0x2a) = 0;
    dVar16 = (double)((float)piVar6[5] * (float)piVar6[5]);
    iVar9 = 0;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar8 = iVar8 + 1) {
      puVar3 = (ushort *)FUN_80060868(iVar2,iVar8);
      uVar4 = FUN_800607f4((int)puVar3);
      if (*(byte *)(param_3 + 0x25) == uVar4) {
        dVar18 = (double)FLOAT_803e4c5c;
        iVar11 = iVar9;
        iVar12 = iVar10;
        for (uVar4 = (uint)*puVar3; (int)uVar4 < (int)(uint)puVar3[10]; uVar4 = uVar4 + 1) {
          puVar5 = (ushort *)FUN_80060858(iVar2,uVar4);
          iVar7 = 0;
          iVar13 = iVar11;
          iVar14 = iVar12;
          do {
            FUN_8006076c((short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar5 * 6),&local_a8);
            dVar15 = (double)(float)((double)((float)((double)local_a8 - dVar19) *
                                              (float)((double)local_a8 - dVar19) +
                                             (float)((double)local_a0 - dVar17) *
                                             (float)((double)local_a0 - dVar17)) / dVar16);
            if (dVar18 < dVar15) {
              dVar15 = dVar18;
            }
            *(float *)(*piVar6 + iVar14) = (float)(dVar18 - (double)(float)(dVar15 * dVar15));
            local_80 = (double)(longlong)(int)local_a4;
            *(short *)(piVar6[1] + iVar13) = (short)(int)local_a4;
            iVar14 = iVar14 + 4;
            iVar13 = iVar13 + 2;
            iVar12 = iVar12 + 4;
            iVar11 = iVar11 + 2;
            iVar10 = iVar10 + 4;
            iVar9 = iVar9 + 2;
            puVar5 = puVar5 + 1;
            iVar7 = iVar7 + 1;
          } while (iVar7 < 3);
        }
        bVar1 = *(byte *)((int)piVar6 + 0x2a);
        *(byte *)((int)piVar6 + 0x2a) = bVar1 + 1;
        *(short *)((int)piVar6 + (uint)bVar1 * 2 + 0x1c) = (short)iVar8;
      }
    }
  }
  FUN_80286868();
  return;
}

