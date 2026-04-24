// Function: FUN_801ef9e0
// Entry: 801ef9e0
// Size: 2956 bytes

/* WARNING: Removing unreachable block (ram,0x801f054c) */
/* WARNING: Removing unreachable block (ram,0x801f0544) */
/* WARNING: Removing unreachable block (ram,0x801f053c) */
/* WARNING: Removing unreachable block (ram,0x801efa00) */
/* WARNING: Removing unreachable block (ram,0x801ef9f8) */
/* WARNING: Removing unreachable block (ram,0x801ef9f0) */

void FUN_801ef9e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  undefined2 *puVar2;
  uint uVar3;
  int *piVar4;
  undefined2 *puVar5;
  int iVar6;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  short *psVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  undefined8 extraout_f1_00;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double in_f31;
  double dVar12;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_88;
  undefined2 local_84;
  undefined2 local_82;
  undefined2 local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
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
  puVar2 = (undefined2 *)FUN_80286840();
  iVar8 = *(int *)(puVar2 + 0x26);
  psVar7 = *(short **)(puVar2 + 0x5c);
  uVar9 = extraout_f1;
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    switch(*(undefined2 *)(iVar8 + 0x1a)) {
    case 0:
      bVar1 = false;
      if (*(int *)(puVar2 + 0x7c) == 0) {
        uVar3 = FUN_80020078(0x78);
        bVar1 = uVar3 == 0;
        piVar4 = FUN_80037048(3,&local_88);
        iVar6 = 0;
        while ((iVar6 < local_88 && (bVar1))) {
          if (*(short *)(*piVar4 + 0x46) == 0x139) {
            bVar1 = false;
          }
          piVar4 = piVar4 + 1;
          iVar6 = iVar6 + 1;
        }
      }
      if (bVar1) {
        puVar5 = FUN_8002becc(0x24,0x139);
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar8 + 0xc);
        *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar8 + 0x10);
        *(undefined *)(puVar5 + 2) = *(undefined *)(iVar8 + 4);
        *(undefined *)((int)puVar5 + 5) = *(undefined *)(iVar8 + 5);
        *(undefined *)(puVar5 + 3) = *(undefined *)(iVar8 + 6);
        *(undefined *)((int)puVar5 + 7) = *(undefined *)(iVar8 + 7);
        puVar5[0xf] = 0xffff;
        puVar5[0xd] = 2;
        *(undefined *)(puVar5 + 0xc) = *(undefined *)(iVar8 + 0x1e);
        iVar8 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5,
                             *(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        if (iVar8 != 0) {
          *(undefined4 *)(iVar8 + 0xf4) = 8;
        }
        *(undefined4 *)(puVar2 + 0x7c) = 1;
      }
      break;
    case 1:
      uVar3 = FUN_80020078((int)*psVar7);
      if (((uVar3 != 0) || (*psVar7 == -1)) &&
         (psVar7[2] = psVar7[2] - (ushort)DAT_803dc070, psVar7[2] < 1)) {
        puVar5 = FUN_8002becc(0x28,0x263);
        *(undefined *)(puVar5 + 2) = 0x20;
        *(undefined *)((int)puVar5 + 5) = 2;
        *(undefined *)((int)puVar5 + 7) = 0xff;
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(puVar2 + 6);
        *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(puVar2 + 8);
        *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(puVar2 + 10);
        puVar5[0x10] = 0x50;
        puVar5[0xf] = 0x10f;
        puVar5[0x11] = 0xffff;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xc] = (short)uVar3 + 0x5dc;
        puVar5[0xd] = 0;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xe] = (short)uVar3 + 0x5dc;
        iVar8 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5,
                             *(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        if (iVar8 != 0) {
          uStack_64 = FUN_80022264(0,10);
          uStack_64 = uStack_64 ^ 0x80000000;
          local_68 = 0x43300000;
          *(float *)(iVar8 + 0x24) =
               FLOAT_803e6964 + (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e6978);
        }
        uVar3 = FUN_80022264(0,(int)psVar7[3]);
        psVar7[2] = psVar7[1] + (short)uVar3;
      }
      break;
    case 2:
      uVar3 = FUN_80020078((int)*psVar7);
      if (((uVar3 != 0) || (*psVar7 == -1)) &&
         (psVar7[2] = psVar7[2] - (ushort)DAT_803dc070, psVar7[2] < 1)) {
        puVar5 = FUN_8002becc(0x28,0x263);
        *(undefined *)(puVar5 + 2) = 4;
        *(undefined *)((int)puVar5 + 5) = 2;
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar8 + 8);
        uStack_5c = FUN_80022264(0xffffffd8,0x28);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(puVar5 + 6) =
             *(float *)(iVar8 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
        uStack_64 = FUN_80022264(0xffffffd8,0x28);
        uStack_64 = uStack_64 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e6978);
        *(float *)(puVar5 + 8) = (float)((double)*(float *)(iVar8 + 0x10) + dVar10);
        puVar5[0x10] = 100;
        puVar5[0xf] = 0x10f;
        puVar5[0x11] = 0xffff;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xc] = (short)uVar3 + 0x5dc;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xe] = (short)uVar3 + 0x5dc;
        iVar8 = FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5
                             ,*(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        if (iVar8 != 0) {
          uStack_5c = FUN_80022264(0,10);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          *(float *)(iVar8 + 0x24) =
               FLOAT_803e6968 - (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
        }
        uVar3 = FUN_80022264(0,(int)psVar7[3]);
        psVar7[2] = psVar7[1] + (short)uVar3;
      }
      break;
    case 4:
      uVar3 = FUN_80020078((int)*psVar7);
      if ((uVar3 != 0) || (*psVar7 == -1)) {
        iVar8 = 2;
        do {
          iVar8 = iVar8 + -1;
          puVar5 = FUN_8002becc(0x28,0x263);
          *(undefined *)(puVar5 + 2) = 0x20;
          *(undefined *)((int)puVar5 + 5) = 2;
          *(undefined *)((int)puVar5 + 7) = 0xff;
          *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(puVar2 + 6);
          *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(puVar2 + 8);
          *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(puVar2 + 10);
          puVar5[0x10] = 400;
          puVar5[0xf] = 0xf;
          puVar5[0x11] = 0x222;
          puVar5[0xc] = 0;
          puVar5[0xd] = 0;
          puVar5[0xe] = 0;
          *(undefined *)(puVar5 + 0x12) = 0;
          iVar6 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,
                               5,*(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                               in_r8,in_r9,in_r10);
          uVar9 = extraout_f1_00;
          if (iVar6 != 0) {
            *(byte *)(*(int *)(iVar6 + 0xb8) + 0x120) =
                 *(byte *)(*(int *)(iVar6 + 0xb8) + 0x120) | 2;
            uStack_5c = FUN_80022264(0xffffffdd,0x23);
            uStack_5c = uStack_5c ^ 0x80000000;
            local_60 = 0x43300000;
            *(float *)(iVar6 + 0x24) =
                 FLOAT_803e696c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
            uStack_64 = FUN_80022264(0xffffffdd,0x23);
            uStack_64 = uStack_64 ^ 0x80000000;
            local_68 = 0x43300000;
            *(float *)(iVar6 + 0x2c) =
                 FLOAT_803e696c * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e6978);
            local_74 = FLOAT_803e6970;
            *(float *)(iVar6 + 0x28) = FLOAT_803e6970;
            local_7c = FLOAT_803e6960;
            local_84 = 0;
            local_82 = 0;
            local_80 = 0;
            local_78 = *(float *)(iVar6 + 0x24);
            local_70 = *(float *)(iVar6 + 0x2c);
            in_r8 = 0;
            in_r9 = *DAT_803dd708;
            uVar9 = (**(code **)(in_r9 + 8))(iVar6,0x1a7,&local_84,0x10000,0xffffffff);
          }
        } while (iVar8 != 0);
        FUN_800201ac((int)*psVar7,0);
      }
      break;
    case 5:
      uVar3 = FUN_80020078((int)*psVar7);
      if (((uVar3 != 0) || (*psVar7 == -1)) &&
         (psVar7[2] = psVar7[2] - (ushort)DAT_803dc070, psVar7[2] < 1)) {
        puVar5 = FUN_8002becc(0x24,0x275);
        uVar3 = FUN_80022264(0xffffff81,0x7e);
        *(char *)(puVar5 + 0xc) = (char)uVar3;
        uStack_64 = FUN_80022264(0xffffff9c,100);
        uStack_64 = uStack_64 ^ 0x80000000;
        local_68 = 0x43300000;
        *(float *)(puVar5 + 4) =
             *(float *)(puVar2 + 6) +
             (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e6978);
        *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(puVar2 + 8);
        uStack_5c = FUN_80022264(0xffffff9c,100);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
        *(float *)(puVar5 + 8) = (float)((double)*(float *)(puVar2 + 10) + dVar10);
        puVar5[0xd] = 0x31;
        puVar5[0xe] = 200;
        iVar8 = FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5
                             ,*(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        if (iVar8 != 0) {
          DAT_803de8e8 = DAT_803de8e8 + 1;
        }
        uVar3 = FUN_80022264(0,(int)psVar7[3]);
        psVar7[2] = psVar7[1] + (short)uVar3;
      }
      break;
    case 6:
      uVar3 = FUN_80020078((int)*psVar7);
      if ((uVar3 != 0) || (*psVar7 == -1)) {
        puVar5 = FUN_8002becc(0x24,700);
        uStack_54 = FUN_80022264(0xfffffefc,0x104);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        *(float *)(puVar5 + 4) =
             *(float *)(puVar2 + 6) +
             (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e6978);
        *(float *)(puVar5 + 6) = FLOAT_803e6974 + *(float *)(puVar2 + 8);
        uStack_5c = FUN_80022264(0xffffffb0,0x50);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
        *(float *)(puVar5 + 8) = (float)((double)*(float *)(puVar2 + 10) + dVar10);
        *(undefined *)(puVar5 + 2) = 0x20;
        *(undefined *)((int)puVar5 + 5) = 2;
        *(undefined *)((int)puVar5 + 7) = 0xff;
        puVar5[0xf] = 0xffff;
        *(char *)(puVar5 + 0xc) = (char)((ushort)*puVar2 >> 8);
        FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5,
                     *(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),in_r8,in_r9,
                     in_r10);
        uVar3 = FUN_80022264(2,5);
        dVar11 = (double)FLOAT_803e6960;
        dVar12 = (double)FLOAT_803e6974;
        dVar10 = DOUBLE_803e6978;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          local_7c = (float)dVar11;
          local_84 = 0;
          local_82 = 0;
          local_80 = 0;
          uStack_54 = FUN_80022264(0xffffff38,200);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_78 = (float)((double)CONCAT44(0x43300000,uStack_54) - dVar10);
          uStack_5c = FUN_80022264(0xffffffec,0x14);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          local_70 = (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar10);
          local_74 = (float)dVar12;
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x1a6,&local_84,0x10002,0xffffffff,0);
        }
        FUN_800201ac((int)*psVar7,0);
      }
      break;
    case 7:
      uVar3 = FUN_80020078((int)*psVar7);
      if (((uVar3 != 0) || (*psVar7 == -1)) &&
         (psVar7[2] = psVar7[2] - (ushort)DAT_803dc070, psVar7[2] < 1)) {
        puVar5 = FUN_8002becc(0x28,0x263);
        *(undefined *)(puVar5 + 2) = 4;
        *(undefined *)((int)puVar5 + 5) = 2;
        uStack_5c = FUN_80022264(0xffffffd8,0x28);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        *(float *)(puVar5 + 4) =
             *(float *)(iVar8 + 8) +
             (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6978);
        uStack_64 = FUN_80022264(0,0x14);
        uStack_64 = uStack_64 ^ 0x80000000;
        local_68 = 0x43300000;
        *(float *)(puVar5 + 6) =
             *(float *)(iVar8 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e6978);
        uStack_54 = FUN_80022264(0xffffffd8,0x28);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e6978);
        *(float *)(puVar5 + 8) = (float)((double)*(float *)(iVar8 + 0x10) + dVar10);
        puVar5[0x10] = 0x1c2;
        uVar3 = FUN_80022264(0,2);
        puVar5[0xf] = (short)uVar3 + 0x1cc;
        puVar5[0x11] = 0xffff;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xc] = (short)uVar3 + 0x5dc;
        uVar3 = FUN_80022264(0xfffffe0c,500);
        puVar5[0xe] = (short)uVar3 + 0x5dc;
        FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5,
                     *(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),in_r8,in_r9,
                     in_r10);
        uVar3 = FUN_80022264(0,(int)psVar7[3]);
        psVar7[2] = psVar7[1] + (short)uVar3;
      }
      break;
    case 8:
      uVar3 = FUN_80020078((int)*psVar7);
      if (((uVar3 != 0) || (*psVar7 == -1)) &&
         (psVar7[2] = psVar7[2] - (ushort)DAT_803dc070, psVar7[2] < 1)) {
        puVar5 = FUN_8002becc(0x38,0x4ac);
        uVar9 = FUN_800201ac((int)*psVar7,0);
        uVar3 = FUN_80022264(0xffffff81,0x7e);
        *(char *)(puVar5 + 0x15) = (char)uVar3;
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(puVar2 + 6);
        *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(puVar2 + 8);
        *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(puVar2 + 10);
        puVar5[0xc] = *psVar7;
        puVar5[0x11] = 1;
        iVar8 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5,
                             *(undefined *)(puVar2 + 0x56),0xffffffff,*(uint **)(puVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        if (iVar8 != 0) {
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x1c3,0,2,0xffffffff,0);
        }
        uVar3 = FUN_80022264(0,(int)psVar7[3]);
        psVar7[2] = psVar7[1] + (short)uVar3;
      }
    }
  }
  FUN_8028688c();
  return;
}

