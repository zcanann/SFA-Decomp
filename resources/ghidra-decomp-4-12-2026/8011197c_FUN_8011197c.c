// Function: FUN_8011197c
// Entry: 8011197c
// Size: 1420 bytes

void FUN_8011197c(ushort *param_1)

{
  float fVar1;
  uint uVar2;
  undefined1 *puVar3;
  undefined8 local_18;
  
  if (DAT_803de248 != '\0') {
    DAT_803a5080 = *(float *)(param_1 + 6);
    DAT_803a5084 = *(float *)(param_1 + 8);
    DAT_803a5088 = *(float *)(param_1 + 10);
    DAT_803a508c = *param_1;
    DAT_803a508e = param_1[1];
    DAT_803a5090 = param_1[2];
    DAT_803de248 = '\0';
  }
  if (DAT_803de24a != DAT_803de249) {
    puVar3 = FUN_800e81bc();
    FLOAT_803dc638 = FLOAT_803dc638 + FLOAT_803e2868;
    if (FLOAT_803dc638 < FLOAT_803e2860) {
      if (DAT_803de24a == 4) {
        FUN_80117e10((int)(FLOAT_803e286c * FLOAT_803dc638),1);
        FUN_80009a28((int)((float)((double)CONCAT44(0x43300000,(uint)(byte)puVar3[10]) -
                                  DOUBLE_803e2888) * (FLOAT_803e2860 - FLOAT_803dc638)),10,1,0,0);
      }
      else if (DAT_803de249 == 4) {
        FUN_80117e10((int)(FLOAT_803e286c * (FLOAT_803e2860 - FLOAT_803dc638)),1);
        FUN_80009a28((int)((float)((double)CONCAT44(0x43300000,(uint)(byte)puVar3[10]) -
                                  DOUBLE_803e2888) * FLOAT_803dc638),10,1,0,0);
      }
    }
    else {
      if (DAT_803de24a == 4) {
        FUN_80117e10(100,1);
        FUN_80009a28(0,10,1,0,0);
        FUN_8000a538((int *)0xbe,0);
        FUN_8000a538((int *)0xc1,0);
      }
      else if (DAT_803de249 == 4) {
        FUN_80117e10(0,1);
        FUN_80009a28((uint)(byte)puVar3[10],10,1,0,0);
      }
      FLOAT_803dc638 = FLOAT_803e2860;
      DAT_803de249 = DAT_803de24a;
    }
    if (FLOAT_803e2870 <= FLOAT_803dc638) {
      fVar1 = -(FLOAT_803e2874 * (FLOAT_803dc638 - FLOAT_803e2870) - FLOAT_803e2860);
      fVar1 = FLOAT_803e2870 * (FLOAT_803e2860 - fVar1 * fVar1) + FLOAT_803e2870;
    }
    else {
      fVar1 = FLOAT_803e2870 * FLOAT_803e2874 * FLOAT_803dc638 * FLOAT_803e2874 * FLOAT_803dc638;
    }
    fVar1 = fVar1 * FLOAT_803e287c * fVar1 * fVar1 +
            FLOAT_803e2870 * fVar1 + FLOAT_803e2878 * fVar1 * fVar1;
    *(float *)(param_1 + 6) =
         fVar1 * (*(float *)(&DAT_8031ac08 + (uint)DAT_803de24a * 0x14) - DAT_803a5080) +
         DAT_803a5080;
    *(float *)(param_1 + 8) =
         fVar1 * (*(float *)(&DAT_8031ac0c + (uint)DAT_803de24a * 0x14) - DAT_803a5084) +
         DAT_803a5084;
    *(float *)(param_1 + 10) =
         fVar1 * (*(float *)(&DAT_8031ac10 + (uint)DAT_803de24a * 0x14) - DAT_803a5088) +
         DAT_803a5088;
    uVar2 = (uint)*(ushort *)(&DAT_8031ac14 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a508c ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803a508c) -
                                     DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac14 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a508c ^ 0x80000000);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                              (float)((double)CONCAT44(0x43300000,
                                                       (int)(short)DAT_803a508c ^ 0x80000000) -
                                     DOUBLE_803e2890));
    }
    uVar2 = (uint)*(ushort *)(&DAT_8031ac16 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a508e ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a508e) -
                                       DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac16 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a508e ^ 0x80000000);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a508e ^ 0x80000000) -
                                       DOUBLE_803e2890));
    }
    uVar2 = (uint)*(ushort *)(&DAT_8031ac18 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a5090 ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a5090) -
                                       DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac18 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a5090 ^ 0x80000000);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a5090 ^ 0x80000000) -
                                       DOUBLE_803e2890));
    }
  }
  return;
}

