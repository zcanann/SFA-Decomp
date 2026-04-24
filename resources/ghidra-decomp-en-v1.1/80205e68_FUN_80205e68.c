// Function: FUN_80205e68
// Entry: 80205e68
// Size: 608 bytes

void FUN_80205e68(int param_1)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  char in_r8;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_78 [2];
  short asStack_70 [4];
  short asStack_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack_3c [12];
  float local_30;
  float local_2c;
  float local_28;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 8) = 0;
  }
  else {
    FUN_8003b9ec(param_1);
    if (*(char *)(iVar5 + 10) != '\0') {
      *(undefined *)(iVar5 + 8) = 1;
      puVar2 = FUN_8000facc();
      local_48 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
      local_44 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
      local_40 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
      dVar6 = FUN_80293900((double)(local_40 * local_40 + local_48 * local_48 + local_44 * local_44)
                          );
      if ((double)FLOAT_803e7064 < dVar6) {
        fVar1 = (float)((double)FLOAT_803e7060 / dVar6);
        local_48 = local_48 * fVar1;
        dVar12 = (double)local_48;
        local_44 = local_44 * fVar1;
        dVar11 = (double)local_44;
        local_40 = local_40 * fVar1;
        dVar10 = (double)local_40;
        dVar6 = (double)FLOAT_803e7068;
        local_54 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
        local_50 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
        local_4c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
        dVar6 = (double)FLOAT_803e706c;
        dVar9 = (double)(float)(dVar6 * dVar12);
        dVar8 = (double)(float)(dVar6 * dVar11);
        local_60 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
        local_5c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
        local_58 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
        FUN_80012d20(&local_54,asStack_68);
        uVar7 = FUN_80012d20(&local_60,asStack_70);
        iVar3 = FUN_800128fc(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_68,
                             asStack_70,auStack_78,(undefined *)0x0,0);
        if (iVar3 == 0) {
          *(undefined *)(iVar5 + 8) = 0;
          (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        }
      }
      if (*(short *)(iVar5 + 4) < 1) {
        if (*(char *)(iVar5 + 8) != '\0') {
          local_30 = FLOAT_803e7070;
          local_2c = FLOAT_803e7074;
          local_28 = FLOAT_803e7070;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_3c,0x12,0xffffffff,0);
        }
        uVar4 = FUN_80022264(0xfffffff6,10);
        *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
      }
      else {
        *(short *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (short)(int)FLOAT_803dc074;
      }
    }
  }
  return;
}

