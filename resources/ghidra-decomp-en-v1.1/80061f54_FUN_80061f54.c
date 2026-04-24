// Function: FUN_80061f54
// Entry: 80061f54
// Size: 308 bytes

uint FUN_80061f54(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,
                 undefined4 *param_6,float *param_7,int param_8)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  fVar1 = FLOAT_803df8d8;
  iVar4 = 0;
  iVar5 = 0;
  iVar6 = *(int *)(param_1 + 100);
  DAT_803ddb72 = 0;
  if (0 < param_4) {
    do {
      iVar2 = 1;
      if (*(float *)(iVar6 + 0x1c) * param_7[2] +
          *(float *)(iVar6 + 0x14) * *param_7 + *(float *)(iVar6 + 0x18) * param_7[1] < fVar1) {
        iVar2 = -1;
      }
      if (iVar2 == 1) {
        DAT_803ddb72 = DAT_803ddb72 + 1;
        puVar3 = (undefined4 *)(param_5 + iVar4 * 0xc);
        *param_6 = *puVar3;
        param_6[1] = puVar3[1];
        param_6[2] = puVar3[2];
        if (param_8 <= iVar5 + 1) {
          return 0;
        }
        puVar3 = (undefined4 *)(param_5 + (iVar4 + 1) * 0xc);
        param_6[3] = *puVar3;
        param_6[4] = puVar3[1];
        param_6[5] = puVar3[2];
        if (param_8 <= iVar5 + 2) {
          return 0;
        }
        puVar3 = (undefined4 *)(param_5 + (iVar4 + 2) * 0xc);
        param_6[6] = *puVar3;
        param_6[7] = puVar3[1];
        param_6[8] = puVar3[2];
        param_6 = param_6 + 9;
        iVar5 = iVar5 + 3;
        if (param_8 <= iVar5) {
          return 0;
        }
      }
      iVar4 = iVar4 + 3;
      param_7 = param_7 + 5;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return (uint)(-(int)DAT_803ddb72 & ~(int)DAT_803ddb72) >> 0x1f;
}

