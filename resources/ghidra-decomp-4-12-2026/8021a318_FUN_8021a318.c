// Function: FUN_8021a318
// Entry: 8021a318
// Size: 732 bytes

void FUN_8021a318(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  puVar5 = *(uint **)(param_9 + 0xb8);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    sVar1 = *(short *)(iVar6 + 0x1a);
    if (sVar1 == 4) {
      uVar2 = FUN_80020078((int)*(short *)(puVar5 + 1));
      if ((uVar2 != 0) &&
         (*(ushort *)(puVar5 + 2) = *(short *)(puVar5 + 2) - (ushort)DAT_803dc070,
         *(short *)(puVar5 + 2) < 1)) {
        puVar4 = FUN_8002becc(0x24,0x6bd);
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
        *(undefined *)(puVar4 + 2) = 1;
        *(undefined *)((int)puVar4 + 5) = 1;
        *(undefined *)(puVar4 + 3) = 0xff;
        *(undefined *)((int)puVar4 + 7) = 0xfa;
        if (*(char *)(param_9 + 0xac) == '\x02') {
          *(undefined *)((int)puVar4 + 0x19) = 4;
        }
        else {
          *(undefined *)((int)puVar4 + 0x19) = 1;
        }
        puVar4 = (undefined2 *)
                 FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4
                              ,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        if (puVar4 != (undefined2 *)0x0) {
          puVar4[1] = 0;
          uVar2 = FUN_80022264(0,0xffff);
          *puVar4 = (short)uVar2;
          dVar7 = (double)FUN_802945e0();
          *(float *)(puVar4 + 0x12) =
               FLOAT_803e7650 *
               FLOAT_803e7654 *
               (float)((double)(float)((double)CONCAT44(0x43300000,*puVar5 ^ 0x80000000) -
                                      DOUBLE_803e7648) * -dVar7);
          uVar2 = FUN_80022264(0,1000);
          *(float *)(puVar4 + 0x14) =
               FLOAT_803e7650 *
               (float)((double)CONCAT44(0x43300000,*puVar5 ^ 0x80000000) - DOUBLE_803e7648) *
               FLOAT_803e7660 *
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e7648);
          dVar7 = (double)FUN_80294964();
          *(float *)(puVar4 + 0x16) =
               FLOAT_803e7650 *
               FLOAT_803e7654 *
               (float)((double)(float)((double)CONCAT44(0x43300000,*puVar5 ^ 0x80000000) -
                                      DOUBLE_803e7648) * -dVar7);
          *(int *)(puVar4 + 0x62) = param_9;
        }
        uVar2 = FUN_80022264(0,(int)*(short *)((int)puVar5 + 10));
        *(short *)(puVar5 + 2) = *(short *)((int)puVar5 + 6) + (short)uVar2;
      }
    }
    else {
      if (sVar1 < 4) {
        if (sVar1 < 3) {
          return;
        }
      }
      else if (sVar1 != 9) {
        return;
      }
      uVar2 = FUN_80020078((int)*(short *)(puVar5 + 1));
      if (uVar2 != 0) {
        if (*(short *)(iVar6 + 0x1a) == 3) {
          uVar3 = 0;
        }
        else {
          uVar3 = 4;
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar3,param_9,0xffffffff);
      }
    }
  }
  return;
}

