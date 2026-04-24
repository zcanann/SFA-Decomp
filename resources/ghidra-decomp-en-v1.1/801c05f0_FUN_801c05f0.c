// Function: FUN_801c05f0
// Entry: 801c05f0
// Size: 624 bytes

void FUN_801c05f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  int iVar4;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (uVar1 = FUN_80020078(0x26b), uVar1 != 0)) {
    FUN_800201ac(0x26b,0);
    piVar2 = FUN_80037048(4,local_28);
    iVar4 = 0;
    if (0 < local_28[0]) {
      do {
        in_r8 = *piVar2;
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326928) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692a) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692c) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692e) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326930) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326932) {
          iVar4 = iVar4 + 1;
        }
        piVar2 = piVar2 + 1;
        local_28[0] = local_28[0] + -1;
      } while (local_28[0] != 0);
    }
    if (iVar4 < 10) {
      uVar1 = FUN_80022264(0,5);
      puVar3 = FUN_8002becc(0x30,(&DAT_80326928)[uVar1]);
      if (puVar3 != (undefined2 *)0x0) {
        *(undefined *)(puVar3 + 0xd) = 0x14;
        puVar3[0x16] = 0xffff;
        puVar3[0xe] = 0xffff;
        uStack_1c = FUN_80022264(0xfffffea2,0x15e);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(puVar3 + 4) =
             *(float *)(param_9 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 6) = FLOAT_803e5a24 + *(float *)(param_9 + 0x10);
        uStack_14 = FUN_80022264(0xfffffea2,0x15e);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        dVar6 = (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 8) = (float)((double)*(float *)(param_9 + 0x14) + dVar6);
        puVar3[0x12] = 0xffff;
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
        *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
        puVar3[0x17] = 3;
        iVar5 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                             in_r8,in_r9,in_r10);
        if (iVar5 != 0) {
          iVar4 = 3;
          do {
            FUN_800972fc(iVar5,2,2,100,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  return;
}

