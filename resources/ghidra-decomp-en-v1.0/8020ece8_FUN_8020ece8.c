// Function: FUN_8020ece8
// Entry: 8020ece8
// Size: 1316 bytes

/* WARNING: Removing unreachable block (ram,0x8020f1e4) */

void FUN_8020ece8(undefined2 *param_1,short *param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  char cVar6;
  int iVar4;
  undefined2 uVar5;
  undefined uVar7;
  int *piVar8;
  int iVar9;
  byte bVar10;
  undefined4 uVar11;
  undefined8 in_f31;
  double dVar12;
  double dVar13;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar8 = *(int **)(param_1 + 0x5c);
  sVar1 = *param_2;
  if (sVar1 == 0x5e3) {
    *(undefined *)(piVar8 + 0x9f) = 0;
    *(undefined *)((int)piVar8 + 0x27e) = 0;
    goto LAB_8020f1e4;
  }
  if (sVar1 < 0x5e3) {
    if (sVar1 == 0x5da) {
      uVar5 = FUN_800221a0(0,0xffff);
      param_1[2] = uVar5;
      uVar5 = FUN_800221a0(0,0xffff);
      param_1[1] = uVar5;
      uVar5 = FUN_800221a0(0,0xffff);
      *param_1 = uVar5;
      uVar7 = FUN_800221a0(0,0xff);
      *(undefined *)(piVar8 + 0x9f) = uVar7;
      uVar7 = FUN_800221a0(0xfffffff6,10);
      *(undefined *)((int)piVar8 + 0x27e) = uVar7;
      uVar7 = FUN_800221a0(0xfffffff6,10);
      *(undefined *)((int)piVar8 + 0x27f) = uVar7;
      uVar7 = FUN_800221a0(0xfffffff6,10);
      *(undefined *)(piVar8 + 0xa0) = uVar7;
      goto LAB_8020f1e4;
    }
    if (sVar1 < 0x5da) {
      if (sVar1 == 0x5d7) {
        piVar8[0x9d] = 0x4ab05;
        piVar8[0x9e] = 0x4ab0b;
      }
      else if (sVar1 < 0x5d7) {
        if (sVar1 == 0x5d5) {
          piVar8[0x9d] = 0x4aaf7;
          piVar8[0x9e] = 0x4ab08;
        }
        else if (0x5d4 < sVar1) {
          piVar8[0x9d] = 0x4ab03;
          piVar8[0x9e] = 0x4ab09;
        }
      }
      else if (sVar1 < 0x5d9) {
        piVar8[0x9d] = 0x4ab04;
        piVar8[0x9e] = 0x4ab0a;
      }
      goto LAB_8020f1e4;
    }
    if (sVar1 != 0x5dd) {
      if ((0x5dc < sVar1) && (0x5e1 < sVar1)) {
        bVar10 = *(byte *)((int)param_2 + 0x1b);
        FUN_8002b884(param_1,(uint)bVar10);
        *(undefined *)(param_1 + 0x1b) = (&DAT_803dc210)[bVar10];
        for (bVar10 = 0; bVar10 < 0xb; bVar10 = bVar10 + 1) {
          iVar9 = *(int *)(param_1 + 0x26);
          cVar6 = FUN_8002e04c();
          if (cVar6 != '\0') {
            iVar4 = FUN_8002bdf4(0x20,0x5da);
            *(undefined *)(iVar4 + 4) = *(undefined *)(iVar9 + 4);
            *(undefined *)(iVar4 + 6) = *(undefined *)(iVar9 + 6);
            *(undefined *)(iVar4 + 5) = *(undefined *)(iVar9 + 5);
            *(undefined *)(iVar4 + 7) = *(undefined *)(iVar9 + 7);
            *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_1 + 6);
            *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_1 + 8);
            *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(param_1 + 10);
            FUN_8002df90(iVar4,5,(int)*(char *)(param_1 + 0x56),0xffffffff,0);
          }
        }
      }
      goto LAB_8020f1e4;
    }
  }
  else {
    if (sVar1 == 0x61e) {
      *(undefined *)(piVar8 + 0x9f) = 0;
      goto LAB_8020f1e4;
    }
    if (0x61d < sVar1) {
      if (sVar1 == 0x80f) {
        iVar9 = FUN_8002e0b4(0x42fe7);
        iVar4 = FUN_8002e0b4(0x4305a);
        dVar12 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(iVar9 + 0x10));
        uVar2 = FUN_800221a0(0xfffffc18,1000);
        piVar8[0x99] = (int)((float)((double)*(float *)(iVar9 + 0x10) - dVar12) +
                            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                   DOUBLE_803e6670));
        uVar2 = FUN_800221a0(0xfffffffb,5);
        piVar8[0x9a] = (int)(*(float *)(iVar4 + 0x10) +
                            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                   DOUBLE_803e6670));
        uVar2 = FUN_800221a0(0,100);
        piVar8[0x9b] = (int)(FLOAT_803e6668 *
                             ((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                     DOUBLE_803e6670) / FLOAT_803e66b4) + FLOAT_803e6668);
        *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * (float)piVar8[0x9b];
        uVar7 = FUN_800221a0(10,0x19);
        *(undefined *)(piVar8 + 0xa0) = uVar7;
        iVar3 = FUN_800221a0(0,1);
        if (iVar3 != 0) {
          *(char *)(piVar8 + 0xa0) = -*(char *)(piVar8 + 0xa0);
          piVar8[0x9c] = 0x8000;
        }
        uVar2 = FUN_800221a0(200,400);
        dVar13 = (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6670);
        dVar12 = (double)FUN_80021704(iVar4 + 0x18,iVar9 + 0x18);
        piVar8[0x97] = (int)(float)((double)FLOAT_803e66c8 * dVar12 + dVar13);
        uVar2 = FUN_800221a0(0,100);
        piVar8[0x98] = (int)((float)piVar8[0x97] *
                            (FLOAT_803e66cc *
                             ((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                     DOUBLE_803e6670) / FLOAT_803e66b4) + FLOAT_803e66cc));
        iVar9 = FUN_8001f4c8(param_1,1);
        *piVar8 = iVar9;
        if (*piVar8 != 0) {
          FUN_8001db2c(*piVar8,2);
          dVar12 = (double)FLOAT_803e665c;
          FUN_8001dd88(dVar12,dVar12,dVar12,*piVar8);
          FUN_8001daf0(*piVar8,0xff,0xff,0xff,0);
          FUN_8001dc38((double)FLOAT_803e66ac,(double)FLOAT_803e66d0,*piVar8);
          FUN_8001d730((double)(FLOAT_803e66d4 * (float)piVar8[0x9b]),*piVar8,0,0xff,0xff,0xff,0x82)
          ;
          FUN_8001d714((double)FLOAT_803e66a0,*piVar8);
        }
      }
      else if ((sVar1 < 0x80f) && (sVar1 == 0x740)) {
        *(undefined *)((int)piVar8 + 0x27d) = 0;
        DAT_803ddd30 = param_1;
      }
      goto LAB_8020f1e4;
    }
    if (sVar1 == 0x5f4) goto LAB_8020f1e4;
    if (0x5f3 < sVar1) {
      if (sVar1 < 0x5f6) {
        *(float *)(param_1 + 4) = FLOAT_803e66d8;
      }
      goto LAB_8020f1e4;
    }
    if (sVar1 < 0x5ed) goto LAB_8020f1e4;
  }
  *(undefined *)((int)piVar8 + 0x27d) = 0;
LAB_8020f1e4:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

