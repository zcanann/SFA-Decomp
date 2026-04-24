// Function: FUN_8021a100
// Entry: 8021a100
// Size: 508 bytes

void FUN_8021a100(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double extraout_f1;
  
  iVar3 = FUN_80286838();
  iVar8 = *(int *)(iVar3 + 0x4c);
  iVar7 = *(int *)(iVar3 + 0xb8);
  dVar10 = (double)FUN_80137cd0();
  uVar4 = FUN_8002e144();
  if ((uVar4 & 0xff) != 0) {
    for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar9 = iVar9 + 1) {
      if ((*(char *)(param_11 + iVar9 + 0x81) == '\n') &&
         (uVar4 = FUN_80020078((int)*(short *)(iVar7 + 4)), uVar4 != 0)) {
        dVar10 = (double)FUN_800201ac(0x631,1);
      }
      sVar1 = *(short *)(iVar8 + 0x1a);
      if ((sVar1 == 9) || (((sVar1 < 9 && (sVar1 < 5)) && (2 < sVar1)))) {
        puVar6 = *(uint **)(iVar3 + 0xb8);
        uVar4 = FUN_80020078((int)*(short *)(puVar6 + 1));
        if (uVar4 != 0) {
          puVar5 = FUN_8002becc(0x24,0x6bd);
          *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
          *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
          *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
          *(undefined *)(puVar5 + 2) = 1;
          *(undefined *)((int)puVar5 + 5) = 1;
          *(undefined *)(puVar5 + 3) = 0xff;
          *(undefined *)((int)puVar5 + 7) = 0xff;
          *(undefined *)((int)puVar5 + 0x19) = 2;
          puVar5 = (undefined2 *)
                   FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar5,5,0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
          dVar10 = extraout_f1;
          if (puVar5 != (undefined2 *)0x0) {
            puVar5[1] = 0;
            uVar4 = FUN_80022264(0,0xffff);
            *puVar5 = (short)uVar4;
            uVar4 = FUN_80022264(-(int)*(short *)((int)puVar6 + 10),
                                 (int)*(short *)((int)puVar6 + 10));
            param_2 = DOUBLE_803e7648;
            fVar2 = FLOAT_803e7640;
            *(float *)(puVar5 + 0x12) =
                 FLOAT_803e7640 *
                 (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7648);
            *(float *)(puVar5 + 0x14) =
                 fVar2 * (float)((double)CONCAT44(0x43300000,*puVar6 ^ 0x80000000) - param_2);
            uVar4 = FUN_80022264(-(int)*(short *)((int)puVar6 + 10),
                                 (int)*(short *)((int)puVar6 + 10));
            dVar10 = (double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                    DOUBLE_803e7648);
            *(float *)(puVar5 + 0x16) = (float)((double)FLOAT_803e7640 * dVar10);
            *(int *)(puVar5 + 0x62) = iVar3;
          }
        }
      }
    }
  }
  FUN_80286884();
  return;
}

