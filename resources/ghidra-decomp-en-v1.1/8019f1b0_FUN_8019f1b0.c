// Function: FUN_8019f1b0
// Entry: 8019f1b0
// Size: 1908 bytes

/* WARNING: Type propagation algorithm not settling */

void FUN_8019f1b0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  ushort *puVar2;
  int iVar3;
  uint uVar4;
  char cVar6;
  int iVar5;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 extraout_r4_01;
  undefined4 extraout_r4_02;
  undefined4 extraout_r4_03;
  undefined4 extraout_r4_04;
  int iVar7;
  float *pfVar8;
  undefined4 in_r6;
  undefined4 uVar9;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  float *pfVar11;
  bool bVar12;
  double dVar13;
  double extraout_f1;
  double extraout_f1_00;
  double dVar14;
  undefined8 uVar15;
  float local_48 [2];
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined8 local_28;
  
  puVar2 = (ushort *)FUN_80286838();
  iVar10 = *(int *)(puVar2 + 0x26);
  pfVar11 = *(float **)(puVar2 + 0x5c);
  iVar3 = FUN_8002bac4();
  FUN_8002ba84();
  uVar4 = FUN_80020078((int)*(short *)(iVar10 + 0x22));
  if (uVar4 != 0) {
    puVar2[3] = puVar2[3] | 0x4000;
    *(byte *)(pfVar11 + 0x8b) = *(byte *)(pfVar11 + 0x8b) & 0xfe;
    FUN_8002cf80((int)puVar2);
    FUN_8003709c((int)puVar2,0x20);
    FUN_8003709c((int)puVar2,3);
  }
  if ((pfVar11[0x8c] == 2.8026e-45) && (uVar4 = FUN_80020078(0x66), uVar4 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(6,puVar2,0xffffffff);
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  else {
    uVar4 = FUN_800803dc(pfVar11);
    if (uVar4 == 0) {
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      if (pfVar11[0x8c] == 0.0) {
        local_48[1] = 3.50325e-44;
        cVar6 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e4ee4,pfVar11 + 0x49,puVar2,local_48 + 1,0);
        if (cVar6 == '\0') {
          pfVar11[0x8c] = 1.4013e-45;
          FUN_800803f8(pfVar11 + 0x8e);
        }
      }
      else {
        uVar4 = FUN_8008038c(500);
        if (uVar4 != 0) {
          uVar4 = FUN_80022264(0,3);
          FUN_80039368((uint)puVar2,(undefined *)(pfVar11 + 0x1b),
                       *(ushort *)((int)pfVar11[0x90] + uVar4 * 2));
        }
        FUN_80039030((int)puVar2,(char *)(pfVar11 + 0x1b));
        if ((pfVar11[0x8c] == 1.4013e-45) || (pfVar11[0x8c] == 2.8026e-45)) {
          dVar13 = (double)pfVar11[0x8f];
          FUN_802229a8(dVar13,(double)(float)((double)FLOAT_803e4ed0 * dVar13),
                       (double)(float)((double)FLOAT_803e4ee8 * dVar13),(int)puVar2,pfVar11 + 0x49,
                       '\x01');
          iVar7 = 0x1e;
          FUN_80222ba0((double)FLOAT_803e4ed0,(double)FLOAT_803e4eec,puVar2,(float *)(puVar2 + 0x12)
                       ,0x1e);
          dVar13 = (double)*(float *)(puVar2 + 0x12);
          dVar14 = (double)*(float *)(puVar2 + 0x14);
          param_3 = (double)*(float *)(puVar2 + 0x16);
          uVar9 = extraout_r4;
          FUN_8002ba34(dVar13,dVar14,param_3,(int)puVar2);
          if (pfVar11[0x8c] == 1.4013e-45) {
            if ((pfVar11[0x8d] != -NAN) &&
               (uVar4 = FUN_80020078((int)pfVar11[0x8d] + 0xb2a), uVar4 != 0)) {
              pfVar11[0x8c] = 2.8026e-45;
              FUN_800201ac(0x66,0);
              iVar7 = *DAT_803dd6e8;
              (**(code **)(iVar7 + 0x58))
                        (*(undefined4 *)(&DAT_80323778 + (int)pfVar11[0x8d] * 4),0x5d1);
              dVar13 = (double)FUN_80080404(pfVar11 + 0x8e,
                                            (short)*(undefined4 *)
                                                    (&DAT_80323778 + (int)pfVar11[0x8d] * 4));
              uVar9 = extraout_r4_00;
            }
            FUN_8019e970(dVar13,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar2,
                         uVar9,iVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
            goto LAB_8019f90c;
          }
          if (pfVar11[0x8c] == 2.8026e-45) {
            pfVar8 = (float *)0x0;
            uVar15 = FUN_80036f50(3,puVar2,(float *)0x0);
            iVar7 = (int)((ulonglong)uVar15 >> 0x20);
            uVar9 = (undefined4)uVar15;
            dVar13 = extraout_f1;
            if ((iVar7 == 0) ||
               (dVar13 = (double)FUN_800217c8((float *)(iVar7 + 0x18),pfVar11 + 6),
               uVar9 = extraout_r4_01, (double)FLOAT_803dcaa0 <= dVar13)) {
              if (iVar7 != 0) {
                uVar9 = FUN_8002bac4();
                dVar13 = (double)FUN_8014cae4(iVar7,uVar9);
                uVar9 = extraout_r4_04;
              }
            }
            else {
              in_r6 = 0;
              pfVar8 = pfVar11;
              FUN_8019eae4(dVar13,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                           iVar7,(int)pfVar11,0,in_r7,in_r8,in_r9,in_r10);
              iVar5 = FUN_8002bac4();
              dVar13 = (double)FUN_800217c8((float *)(iVar5 + 0x18),(float *)(iVar7 + 0x18));
              if (dVar13 <= (double)FLOAT_803dcaa4) {
                uVar9 = FUN_8002bac4();
                dVar13 = (double)FUN_8014cae4(iVar7,uVar9);
                uVar9 = extraout_r4_03;
              }
              else {
                FUN_8014cae4(iVar7,puVar2);
                if (puVar2[0x50] != 0xd) {
                  pfVar8 = (float *)0x0;
                  FUN_8003042c((double)*(float *)(puVar2 + 0x4c),dVar14,param_3,param_4,param_5,
                               param_6,param_7,param_8,puVar2,0xd,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
                dVar14 = (double)FLOAT_803dc074;
                dVar13 = (double)FUN_8002fb40((double)FLOAT_803e4ec4,dVar14);
                uVar9 = extraout_r4_02;
              }
            }
            FUN_8019e970(dVar13,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar2,
                         uVar9,pfVar8,in_r6,in_r7,in_r8,in_r9,in_r10);
          }
        }
        dVar13 = (double)FUN_800217c8((float *)(puVar2 + 0xc),(float *)(iVar3 + 0x18));
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1a) / 2 ^ 0x80000000);
        bVar12 = dVar13 < (double)(float)(local_28 - DOUBLE_803e4eb8);
        if (pfVar11[0x8c] == 2.8026e-45) {
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x18) ^ 0x80000000);
          local_48[0] = (float)(local_28 - DOUBLE_803e4eb8);
          dVar14 = DOUBLE_803e4eb8;
          uVar4 = FUN_800803dc(pfVar11 + 0x8e);
          if (uVar4 != 0) {
            iVar3 = FUN_8002bac4();
            if (((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) &&
               (iVar3 = FUN_80080434(pfVar11 + 0x8e), iVar3 != 0)) {
              (**(code **)(*DAT_803dd6d4 + 0x48))(6,puVar2,0xffffffff);
              (**(code **)(*DAT_803dd6e8 + 0x60))();
              goto LAB_8019f90c;
            }
            local_28 = (double)(longlong)(int)pfVar11[0x8e];
            dVar13 = (double)(**(code **)(*DAT_803dd6e8 + 0x5c))((int)pfVar11[0x8e]);
          }
          if ((!bVar12) &&
             (iVar3 = FUN_80036f50(3,puVar2,local_48), dVar13 = extraout_f1_00, iVar3 != 0)) {
            bVar12 = true;
          }
          uVar4 = FUN_80020078((int)pfVar11[0x8d] + 0xb2e);
          if (uVar4 != 0) {
            pfVar11[0x8c] = 4.2039e-45;
            (**(code **)(*DAT_803dd6e8 + 0x60))();
            FUN_8000bb38((uint)puVar2,0x109);
            dVar13 = (double)FUN_800803f8(pfVar11 + 0x8e);
          }
        }
        else {
          *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
          iVar7 = *(int *)(puVar2 + 0x5c);
          iVar3 = FUN_8002bac4();
          iVar5 = *(int *)(puVar2 + 0x26);
          bVar1 = false;
          dVar13 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc));
          dVar14 = DOUBLE_803e4eb8;
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000);
          if (((dVar13 < (double)(float)(local_28 - DOUBLE_803e4eb8)) &&
              (*(int *)(iVar7 + 0x230) == 3)) && ((puVar2[0x58] & 0x1000) == 0)) {
            bVar1 = true;
          }
          if (bVar1) {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xef;
          }
          else {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 0x10;
          }
        }
        if (pfVar11[0x8c] == 4.2039e-45) {
          if (*(char *)(pfVar11 + 0x91) < '\0') {
            if (bVar12) {
              dVar13 = (double)(**(code **)(*DAT_803dd6d4 + 0x48))(1,puVar2,0xffffffff);
              pfVar11[0x2c] = 1.4013e-45;
            }
            iVar3 = FUN_8002bac4();
            uVar9 = 1;
            FUN_8019eae4(dVar13,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,iVar3,
                         (int)pfVar11,1,in_r7,in_r8,in_r9,in_r10);
            dVar13 = (double)FLOAT_803dc074;
            iVar3 = FUN_8002fb40((double)pfVar11[0x2a],dVar13);
            if (iVar3 != 0) {
              uVar4 = FUN_8008038c(2);
              if (uVar4 == 0) {
                FUN_8003042c((double)FLOAT_803e4eb0,dVar13,param_3,param_4,param_5,param_6,param_7,
                             param_8,puVar2,0,0,uVar9,in_r7,in_r8,in_r9,in_r10);
              }
              else {
                FUN_8003042c((double)FLOAT_803e4eb0,dVar13,param_3,param_4,param_5,param_6,param_7,
                             param_8,puVar2,2,0,uVar9,in_r7,in_r8,in_r9,in_r10);
              }
            }
          }
          else {
            local_34 = *(undefined4 *)(iVar10 + 8);
            local_30 = *(undefined4 *)(iVar10 + 0xc);
            local_2c = *(undefined4 *)(iVar10 + 0x10);
            local_40 = *(undefined2 *)(pfVar11 + 0x34);
            local_3e = 0;
            local_3c = 0;
            puVar2[1] = 0;
            puVar2[2] = 0;
            iVar3 = FUN_80114a58(puVar2,&local_40,-1,&FLOAT_803dcaac,&DAT_803dcab0,in_r8,in_r9,
                                 in_r10);
            if (iVar3 != 0) {
              *(byte *)(pfVar11 + 0x91) = *(byte *)(pfVar11 + 0x91) & 0x7f | 0x80;
              FUN_800201ac(0x66,0);
            }
            FUN_8002fb40((double)FLOAT_803dcaac,(double)FLOAT_803dc074);
          }
        }
      }
    }
    else {
      *(byte *)(pfVar11 + 0x8b) = *(byte *)(pfVar11 + 0x8b) | 1;
      pfVar11[0x31] = 0.0;
      if (*(int *)(puVar2 + 0x7a) < 0) {
        if ((int)*(short *)(iVar10 + 0x22) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar10 + 0x22),1);
        }
        FUN_80035ff8((int)puVar2);
        puVar2[3] = puVar2[3] | 0x4000;
        *(byte *)(pfVar11 + 0x8b) = *(byte *)(pfVar11 + 0x8b) & 0xfe;
        FUN_8002cf80((int)puVar2);
        FUN_8003709c((int)puVar2,0x20);
        FUN_8003709c((int)puVar2,3);
        puVar2[3] = puVar2[3] | 0x4000;
      }
      else {
        *(int *)(puVar2 + 0x7a) = *(int *)(puVar2 + 0x7a) + -1;
      }
    }
  }
LAB_8019f90c:
  FUN_80286884();
  return;
}

