// Function: FUN_8020f360
// Entry: 8020f360
// Size: 1316 bytes

/* WARNING: Removing unreachable block (ram,0x8020f85c) */
/* WARNING: Removing unreachable block (ram,0x8020f370) */

void FUN_8020f360(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,short *param_10)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  undefined2 *puVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar6;
  int iVar7;
  byte bVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  
  piVar6 = *(int **)(param_9 + 0x5c);
  sVar1 = *param_10;
  if (sVar1 == 0x5e3) {
    *(undefined *)(piVar6 + 0x9f) = 0;
    *(undefined *)((int)piVar6 + 0x27e) = 0;
    return;
  }
  if (sVar1 < 0x5e3) {
    if (sVar1 == 0x5da) {
      uVar4 = FUN_80022264(0,0xffff);
      param_9[2] = (short)uVar4;
      uVar4 = FUN_80022264(0,0xffff);
      param_9[1] = (short)uVar4;
      uVar4 = FUN_80022264(0,0xffff);
      *param_9 = (short)uVar4;
      uVar4 = FUN_80022264(0,0xff);
      *(char *)(piVar6 + 0x9f) = (char)uVar4;
      uVar4 = FUN_80022264(0xfffffff6,10);
      *(char *)((int)piVar6 + 0x27e) = (char)uVar4;
      uVar4 = FUN_80022264(0xfffffff6,10);
      *(char *)((int)piVar6 + 0x27f) = (char)uVar4;
      uVar4 = FUN_80022264(0xfffffff6,10);
      *(char *)(piVar6 + 0xa0) = (char)uVar4;
      return;
    }
    if (sVar1 < 0x5da) {
      if (sVar1 == 0x5d7) {
        piVar6[0x9d] = 0x4ab05;
        piVar6[0x9e] = 0x4ab0b;
        return;
      }
      if (0x5d6 < sVar1) {
        if (0x5d8 < sVar1) {
          return;
        }
        piVar6[0x9d] = 0x4ab04;
        piVar6[0x9e] = 0x4ab0a;
        return;
      }
      if (sVar1 == 0x5d5) {
        piVar6[0x9d] = 0x4aaf7;
        piVar6[0x9e] = 0x4ab08;
        return;
      }
      if (sVar1 < 0x5d5) {
        return;
      }
      piVar6[0x9d] = 0x4ab03;
      piVar6[0x9e] = 0x4ab09;
      return;
    }
    if (sVar1 != 0x5dd) {
      if (sVar1 < 0x5dd) {
        return;
      }
      if (sVar1 < 0x5e2) {
        return;
      }
      bVar8 = *(byte *)((int)param_10 + 0x1b);
      uVar9 = FUN_8002b95c((int)param_9,(uint)bVar8);
      *(undefined *)(param_9 + 0x1b) = (&DAT_803dce78)[bVar8];
      for (bVar8 = 0; bVar8 < 0xb; bVar8 = bVar8 + 1) {
        iVar7 = *(int *)(param_9 + 0x26);
        uVar4 = FUN_8002e144();
        if ((uVar4 & 0xff) != 0) {
          puVar5 = FUN_8002becc(0x20,0x5da);
          *(undefined *)(puVar5 + 2) = *(undefined *)(iVar7 + 4);
          *(undefined *)(puVar5 + 3) = *(undefined *)(iVar7 + 6);
          *(undefined *)((int)puVar5 + 5) = *(undefined *)(iVar7 + 5);
          *(undefined *)((int)puVar5 + 7) = *(undefined *)(iVar7 + 7);
          *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(param_9 + 6);
          *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(param_9 + 8);
          *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(param_9 + 10);
          uVar9 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,
                               5,*(undefined *)(param_9 + 0x56),0xffffffff,(uint *)0x0,in_r8,in_r9,
                               in_r10);
        }
      }
      return;
    }
  }
  else {
    if (sVar1 == 0x61e) {
      *(undefined *)(piVar6 + 0x9f) = 0;
      return;
    }
    if (0x61d < sVar1) {
      if (sVar1 == 0x80f) {
        iVar7 = FUN_8002e1ac(0x42fe7);
        iVar2 = FUN_8002e1ac(0x4305a);
        dVar10 = (double)(*(float *)(iVar2 + 0x10) - *(float *)(iVar7 + 0x10));
        uVar4 = FUN_80022264(0xfffffc18,1000);
        piVar6[0x99] = (int)((float)((double)*(float *)(iVar7 + 0x10) - dVar10) +
                            (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                   DOUBLE_803e7308));
        uVar4 = FUN_80022264(0xfffffffb,5);
        piVar6[0x9a] = (int)(*(float *)(iVar2 + 0x10) +
                            (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                   DOUBLE_803e7308));
        uVar4 = FUN_80022264(0,100);
        piVar6[0x9b] = (int)(FLOAT_803e7300 *
                             ((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                     DOUBLE_803e7308) / FLOAT_803e734c) + FLOAT_803e7300);
        *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * (float)piVar6[0x9b];
        uVar4 = FUN_80022264(10,0x19);
        *(char *)(piVar6 + 0xa0) = (char)uVar4;
        uVar4 = FUN_80022264(0,1);
        if (uVar4 != 0) {
          *(char *)(piVar6 + 0xa0) = -*(char *)(piVar6 + 0xa0);
          piVar6[0x9c] = 0x8000;
        }
        uVar4 = FUN_80022264(200,400);
        dVar11 = (double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7308);
        dVar10 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(iVar7 + 0x18));
        piVar6[0x97] = (int)(float)((double)FLOAT_803e7360 * dVar10 + dVar11);
        uVar4 = FUN_80022264(0,100);
        piVar6[0x98] = (int)((float)piVar6[0x97] *
                            (FLOAT_803e7364 *
                             ((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                     DOUBLE_803e7308) / FLOAT_803e734c) + FLOAT_803e7364));
        piVar3 = FUN_8001f58c((int)param_9,'\x01');
        *piVar6 = (int)piVar3;
        if (*piVar6 == 0) {
          return;
        }
        FUN_8001dbf0(*piVar6,2);
        dVar10 = (double)FLOAT_803e72f4;
        FUN_8001de4c(dVar10,dVar10,dVar10,(int *)*piVar6);
        FUN_8001dbb4(*piVar6,0xff,0xff,0xff,0);
        dVar11 = (double)FLOAT_803e7368;
        FUN_8001dcfc((double)FLOAT_803e7344,dVar11,*piVar6);
        FUN_8001d7f4((double)(FLOAT_803e736c * (float)piVar6[0x9b]),dVar11,dVar10,param_4,param_5,
                     param_6,param_7,param_8,*piVar6,0,0xff,0xff,0xff,0x82,in_r9,in_r10);
        FUN_8001d7d8((double)FLOAT_803e7338,*piVar6);
        return;
      }
      if (0x80e < sVar1) {
        return;
      }
      if (sVar1 != 0x740) {
        return;
      }
      *(undefined *)((int)piVar6 + 0x27d) = 0;
      DAT_803de9b0 = param_9;
      return;
    }
    if (sVar1 == 0x5f4) {
      return;
    }
    if (0x5f3 < sVar1) {
      if (0x5f5 < sVar1) {
        return;
      }
      *(float *)(param_9 + 4) = FLOAT_803e7370;
      return;
    }
    if (sVar1 < 0x5ed) {
      return;
    }
  }
  *(undefined *)((int)piVar6 + 0x27d) = 0;
  return;
}

