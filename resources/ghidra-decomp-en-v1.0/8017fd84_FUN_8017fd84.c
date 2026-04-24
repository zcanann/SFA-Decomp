// Function: FUN_8017fd84
// Entry: 8017fd84
// Size: 392 bytes

void FUN_8017fd84(short *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  FUN_80037200(param_1,0x34);
  FUN_80037200(param_1,0x3e);
  iVar4 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(param_2 + 0x14));
  if (iVar4 == 0) {
    dVar6 = (double)(**(code **)(*DAT_803dcaac + 0x6c))(*(undefined4 *)(param_2 + 0x14));
    uVar3 = (uint)*(ushort *)(param_2 + 0x18);
    if (uVar3 < 100) {
      uVar3 = 100;
    }
    fVar1 = (float)(dVar6 / (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                           DOUBLE_803e3860));
    fVar2 = FLOAT_803e3858;
    if ((fVar1 <= FLOAT_803e3858) && (fVar2 = fVar1, fVar1 < FLOAT_803e385c)) {
      fVar2 = FLOAT_803e385c;
    }
    *(float *)(iVar5 + 4) = FLOAT_803e3858 - fVar2;
  }
  else {
    *(float *)(iVar5 + 4) = FLOAT_803e3858;
  }
  *(undefined *)(iVar5 + 0xf) = 0;
  *(float *)(iVar5 + 8) = FLOAT_803e385c;
  FUN_80030304((double)*(float *)(iVar5 + 4),param_1);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1d) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x1c);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  iVar4 = *(int *)(param_1 + 0x32);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x810;
  }
  *(code **)(param_1 + 0x5e) = FUN_8017f8c8;
  return;
}

