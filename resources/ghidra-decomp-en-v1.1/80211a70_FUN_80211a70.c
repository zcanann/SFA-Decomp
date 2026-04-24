// Function: FUN_80211a70
// Entry: 80211a70
// Size: 1560 bytes

/* WARNING: Removing unreachable block (ram,0x80212068) */
/* WARNING: Removing unreachable block (ram,0x80211a80) */

void FUN_80211a70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  char cVar1;
  float fVar2;
  undefined uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar7;
  undefined8 uVar8;
  undefined8 extraout_f1;
  double dVar9;
  double dVar10;
  float local_48;
  ushort local_44 [4];
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_28;
  uint uStack_24;
  
  piVar7 = *(int **)(param_9 + 0x5c);
  if (piVar7[1] != 0) {
    FUN_8001d774(piVar7[1]);
  }
  if (*(int *)(param_9 + 0x62) != 0) {
    *piVar7 = *(int *)(param_9 + 0x62);
    param_9[0x62] = 0;
    param_9[99] = 0;
  }
  uVar4 = FUN_800803dc((float *)(piVar7 + 10));
  if (uVar4 != 0) {
    dVar10 = (double)(float)piVar7[3];
    *(float *)(param_9 + 4) =
         (float)(dVar10 * (double)FLOAT_803dc074 + (double)*(float *)(param_9 + 4));
    if (*piVar7 != 0) {
      iVar5 = FUN_8005a310(*piVar7);
      if (iVar5 == 0) {
        *(undefined4 *)(param_9 + 6) = *(undefined4 *)(*piVar7 + 0xc);
        *(undefined4 *)(param_9 + 8) = *(undefined4 *)(*piVar7 + 0x10);
        *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*piVar7 + 0x14);
      }
      else {
        FUN_80038524(*piVar7,*(undefined4 *)(param_9 + 0x7a),(float *)(param_9 + 6),
                     (undefined4 *)(param_9 + 8),(float *)(param_9 + 10),0);
      }
    }
    iVar5 = FUN_80080434((float *)(piVar7 + 10));
    if (iVar5 != 0) {
      if (*(char *)(piVar7 + 0xb) == '\x02') {
        dVar10 = (double)*(float *)(param_9 + 8);
        param_3 = (double)*(float *)(param_9 + 10);
        FUN_80065a20((double)*(float *)(param_9 + 6),dVar10,param_3,param_9,&local_48,0);
        *(float *)(param_9 + 8) = *(float *)(param_9 + 8) - local_48;
        FUN_8000bb38((uint)param_9,0x2e6);
        FUN_8000bb38((uint)param_9,0x2e8);
      }
      else {
        FUN_8000bb38((uint)param_9,0x2e7);
        FUN_8000bb38((uint)param_9,0x2e9);
      }
    }
    if (piVar7[1] != 0) {
      return;
    }
    iVar5 = FUN_8001cd60(param_9,0xff,0,0,0);
    piVar7[1] = iVar5;
    piVar6 = (int *)FUN_800395a4((int)param_9,0);
    if (piVar6 == (int *)0x0) {
      uVar3 = 0;
    }
    else {
      iVar5 = *piVar6 + 0x10 >> 0x1f;
      *piVar6 = (iVar5 * 0x200 | (uint)((*piVar6 + 0x10) * 0x800000 + iVar5) >> 0x17) - iVar5;
      uVar3 = (undefined)((uint)*piVar6 >> 8);
    }
    if (piVar7[1] == 0) {
      return;
    }
    *(undefined *)(piVar7[1] + 0x4c) = uVar3;
    FUN_8001d7f4((double)FLOAT_803dce9c,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,
                 piVar7[1],0,0xff,0,0,(uint)DAT_803dcea0,in_r9,in_r10);
    FUN_8001de4c((double)FLOAT_803e7400,(double)*(float *)(param_9 + 0x54),(double)FLOAT_803e7400,
                 (int *)piVar7[1]);
    return;
  }
  uVar4 = FUN_800803dc((float *)(piVar7 + 7));
  if (uVar4 != 0) {
    uVar8 = FUN_8000bb38((uint)param_9,0xef);
    if (piVar7[1] == 0) {
      iVar5 = FUN_8001cd60(param_9,0xff,0,0,0);
      piVar7[1] = iVar5;
      uVar8 = extraout_f1;
      if (piVar7[1] != 0) {
        FUN_8001d7f4((double)FLOAT_803dcea4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     piVar7[1],0,0xff,0,0,(uint)DAT_803dcea8,in_r9,in_r10);
        param_3 = (double)FLOAT_803e7400;
        param_2 = (double)*(float *)(param_9 + 0x54);
        uVar8 = FUN_8001de4c(param_3,param_2,param_3,(int *)piVar7[1]);
      }
    }
    iVar5 = FUN_80080434((float *)(piVar7 + 7));
    if (iVar5 != 0) {
      FUN_80211770(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
      return;
    }
  }
  cVar1 = *(char *)(piVar7 + 0xb);
  if (cVar1 == '\x01') {
LAB_80211e70:
    iVar5 = FUN_80080434((float *)(piVar7 + 6));
    fVar2 = FLOAT_803e7400;
    if (iVar5 != 0) {
      iVar5 = *(int *)(param_9 + 0x5c);
      *(float *)(param_9 + 0x14) = FLOAT_803e7400;
      *(float *)(param_9 + 0x12) = fVar2;
      *(float *)(param_9 + 0x16) = fVar2;
      *(undefined *)(iVar5 + 0x2c) = 0;
      FUN_800803f8((undefined4 *)(iVar5 + 0x1c));
      FUN_80080404((float *)(iVar5 + 0x1c),1);
      FUN_80080404((float *)(iVar5 + 0x14),10);
      return;
    }
    if (FLOAT_803e741c < *(float *)(param_9 + 0x14)) {
      *(float *)(param_9 + 0x14) = FLOAT_803e7420 * FLOAT_803dc074 + *(float *)(param_9 + 0x14);
    }
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0x400;
    param_9[1] = param_9[1] + (ushort)DAT_803dc070 * 0x700;
    *(float *)(param_9 + 6) = *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
    *(float *)(param_9 + 8) = *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
    *(float *)(param_9 + 10) =
         *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
  }
  else {
    if (cVar1 < '\x01') {
      if (cVar1 != -1) {
        if (-2 < cVar1) {
          uVar8 = FUN_8000b7dc((int)param_9,0x40);
          iVar5 = FUN_80080434((float *)(piVar7 + 5));
          if (iVar5 != 0) {
            FUN_8002cc9c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
            ;
            return;
          }
        }
        goto LAB_80212004;
      }
      iVar5 = FUN_8002bac4();
      dVar10 = (double)FUN_80021754((float *)(param_9 + 0xc),(float *)(iVar5 + 0x18));
      *(undefined *)(piVar7 + 0xb) = 1;
      *(float *)(param_9 + 0x12) = FLOAT_803e7400;
      dVar9 = FUN_80293900(dVar10);
      *(float *)(param_9 + 0x14) =
           FLOAT_803e7414 * FLOAT_803dceb0 + (float)(dVar9 / (double)FLOAT_803dceac);
      dVar10 = FUN_80293900(dVar10);
      *(float *)(param_9 + 0x16) =
           FLOAT_803e7418 * FLOAT_803dceb0 - (float)(dVar10 / (double)FLOAT_803dceac);
      local_38 = FLOAT_803e7400;
      local_34 = FLOAT_803e7400;
      local_30 = FLOAT_803e7400;
      local_3c = FLOAT_803e7410;
      local_44[2] = 0;
      local_44[1] = 0;
      local_44[0] = *param_9;
      FUN_80021b8c(local_44,(float *)(param_9 + 0x12));
      FUN_8000bb38((uint)param_9,0xf0);
      goto LAB_80211e70;
    }
    if (cVar1 == '\x03') {
      uStack_24 = (int)*(short *)(*(int *)(param_9 + 0x26) + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7428);
      iVar5 = FUN_8002bac4();
      dVar10 = (double)FUN_800217c8((float *)(param_9 + 0xc),(float *)(iVar5 + 0x18));
      if (dVar10 < dVar9) {
        *(undefined *)(piVar7 + 0xb) = 2;
        FUN_80080404((float *)(piVar7 + 7),0x78);
      }
      goto LAB_80212004;
    }
    if ('\x02' < cVar1) goto LAB_80212004;
  }
  (**(code **)(*DAT_803dd708 + 8))(param_9,0x51c,0,1,0xffffffff,0);
  iVar5 = FUN_80080434((float *)(piVar7 + 8));
  if (iVar5 != 0) {
    FUN_80036018((int)param_9);
  }
  FUN_80035eec((int)param_9,0xd,1,0);
  if (piVar7[1] == 0) {
    *(undefined *)(piVar7 + 0xc) = 0;
  }
  else {
    if ((*(char *)(piVar7[1] + 0x4c) != '\0') && (*(char *)(piVar7 + 0xc) == '\0')) {
      FUN_8000bb38((uint)param_9,0x42e);
    }
    *(undefined *)(piVar7 + 0xc) = *(undefined *)(piVar7[1] + 0x4c);
  }
LAB_80212004:
  uVar4 = FUN_800803dc((float *)(piVar7 + 5));
  if ((uVar4 == 0) &&
     (iVar5 = FUN_8005b478((double)*(float *)(param_9 + 6),(double)*(float *)(param_9 + 8)),
     fVar2 = FLOAT_803e7400, iVar5 == -1)) {
    iVar5 = *(int *)(param_9 + 0x5c);
    *(float *)(param_9 + 0x14) = FLOAT_803e7400;
    *(float *)(param_9 + 0x12) = fVar2;
    *(float *)(param_9 + 0x16) = fVar2;
    *(undefined *)(iVar5 + 0x2c) = 0;
    FUN_800803f8((undefined4 *)(iVar5 + 0x1c));
    FUN_80080404((float *)(iVar5 + 0x1c),1);
    FUN_80080404((float *)(iVar5 + 0x14),10);
  }
  return;
}

