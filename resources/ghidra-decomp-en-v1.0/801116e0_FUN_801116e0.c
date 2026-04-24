// Function: FUN_801116e0
// Entry: 801116e0
// Size: 1420 bytes

void FUN_801116e0(ushort *param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  double local_18;
  
  if (DAT_803dd5d0 != '\0') {
    DAT_803a4420 = *(float *)(param_1 + 6);
    DAT_803a4424 = *(float *)(param_1 + 8);
    DAT_803a4428 = *(float *)(param_1 + 10);
    DAT_803a442c = *param_1;
    DAT_803a442e = param_1[1];
    DAT_803a4430 = param_1[2];
    DAT_803dd5d0 = '\0';
  }
  if (DAT_803dd5d2 != DAT_803dd5d1) {
    iVar3 = FUN_800e7f38();
    FLOAT_803db9d8 = FLOAT_803db9d8 + FLOAT_803e1be8;
    if (FLOAT_803db9d8 < FLOAT_803e1be0) {
      if (DAT_803dd5d2 == 4) {
        FUN_80117b68((int)(FLOAT_803e1bec * FLOAT_803db9d8),1);
        FUN_80009a28((int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 10)) -
                                  DOUBLE_803e1c08) * (FLOAT_803e1be0 - FLOAT_803db9d8)),10,1,0,0);
      }
      else if (DAT_803dd5d1 == 4) {
        FUN_80117b68((int)(FLOAT_803e1bec * (FLOAT_803e1be0 - FLOAT_803db9d8)),1);
        FUN_80009a28((int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 10)) -
                                  DOUBLE_803e1c08) * FLOAT_803db9d8),10,1,0,0);
      }
    }
    else {
      if (DAT_803dd5d2 == 4) {
        FUN_80117b68(100,1);
        FUN_80009a28(0,10,1,0,0);
        FUN_8000a518(0xbe,0);
        FUN_8000a518(0xc1,0);
      }
      else if (DAT_803dd5d1 == 4) {
        FUN_80117b68(0,1);
        FUN_80009a28(*(undefined *)(iVar3 + 10),10,1,0,0);
      }
      FLOAT_803db9d8 = FLOAT_803e1be0;
      DAT_803dd5d1 = DAT_803dd5d2;
    }
    if (FLOAT_803e1bf0 <= FLOAT_803db9d8) {
      fVar1 = -(FLOAT_803e1bf4 * (FLOAT_803db9d8 - FLOAT_803e1bf0) - FLOAT_803e1be0);
      fVar1 = FLOAT_803e1bf0 * (FLOAT_803e1be0 - fVar1 * fVar1) + FLOAT_803e1bf0;
    }
    else {
      fVar1 = FLOAT_803e1bf0 * FLOAT_803e1bf4 * FLOAT_803db9d8 * FLOAT_803e1bf4 * FLOAT_803db9d8;
    }
    fVar1 = fVar1 * FLOAT_803e1bfc * fVar1 * fVar1 +
            FLOAT_803e1bf0 * fVar1 + FLOAT_803e1bf8 * fVar1 * fVar1;
    *(float *)(param_1 + 6) =
         fVar1 * (*(float *)(&DAT_80319fb8 + (uint)DAT_803dd5d2 * 0x14) - DAT_803a4420) +
         DAT_803a4420;
    *(float *)(param_1 + 8) =
         fVar1 * (*(float *)(&DAT_80319fbc + (uint)DAT_803dd5d2 * 0x14) - DAT_803a4424) +
         DAT_803a4424;
    *(float *)(param_1 + 10) =
         fVar1 * (*(float *)(&DAT_80319fc0 + (uint)DAT_803dd5d2 * 0x14) - DAT_803a4428) +
         DAT_803a4428;
    uVar2 = (uint)*(ushort *)(&DAT_80319fc4 + (uint)DAT_803dd5d2 * 0x14) - (uint)DAT_803a442c ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e1c10)) <= FLOAT_803e1c00) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803a442c) -
                                     DOUBLE_803e1c08));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_80319fc4 + (uint)DAT_803dd5d2 * 0x14)
                                  - (int)(short)DAT_803a442c ^ 0x80000000);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                              (float)((double)CONCAT44(0x43300000,
                                                       (int)(short)DAT_803a442c ^ 0x80000000) -
                                     DOUBLE_803e1c10));
    }
    uVar2 = (uint)*(ushort *)(&DAT_80319fc6 + (uint)DAT_803dd5d2 * 0x14) - (uint)DAT_803a442e ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e1c10)) <= FLOAT_803e1c00) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a442e) -
                                       DOUBLE_803e1c08));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_80319fc6 + (uint)DAT_803dd5d2 * 0x14)
                                  - (int)(short)DAT_803a442e ^ 0x80000000);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a442e ^ 0x80000000) -
                                       DOUBLE_803e1c10));
    }
    uVar2 = (uint)*(ushort *)(&DAT_80319fc8 + (uint)DAT_803dd5d2 * 0x14) - (uint)DAT_803a4430 ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e1c10)) <= FLOAT_803e1c00) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a4430) -
                                       DOUBLE_803e1c08));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_80319fc8 + (uint)DAT_803dd5d2 * 0x14)
                                  - (int)(short)DAT_803a4430 ^ 0x80000000);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e1c10) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a4430 ^ 0x80000000) -
                                       DOUBLE_803e1c10));
    }
  }
  return;
}

