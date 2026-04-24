// Function: FUN_800e6dbc
// Entry: 800e6dbc
// Size: 428 bytes

undefined4 *
FUN_800e6dbc(undefined8 param_1,double param_2,int param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  int *local_18 [5];
  
  if (param_3 != DAT_803de0fc) {
    if (param_5 == 0) {
      iVar1 = -2;
    }
    else {
      iVar1 = 1;
    }
    DAT_803de0fc = param_3;
    DAT_803de0f8 = FUN_80065fcc(param_1,(double)*(float *)(param_3 + 0x1c),param_2,param_3,local_18,
                                iVar1,0);
    if (0x23 < (int)DAT_803de0f8) {
      DAT_803de0f8 = 0x23;
    }
    uVar3 = DAT_803de0f8;
    puVar2 = &DAT_803a3898;
    if (0 < (int)DAT_803de0f8) {
      uVar4 = DAT_803de0f8 >> 1;
      if (uVar4 != 0) {
        do {
          *puVar2 = *(undefined4 *)*local_18[0];
          puVar2[1] = *(undefined4 *)(*local_18[0] + 4);
          puVar2[2] = *(undefined4 *)(*local_18[0] + 8);
          puVar2[3] = *(undefined4 *)(*local_18[0] + 0xc);
          puVar2[4] = *(undefined4 *)(*local_18[0] + 0x10);
          *(undefined *)(puVar2 + 5) = *(undefined *)(*local_18[0] + 0x14);
          puVar2[6] = *(undefined4 *)local_18[0][1];
          puVar2[7] = *(undefined4 *)(local_18[0][1] + 4);
          puVar2[8] = *(undefined4 *)(local_18[0][1] + 8);
          puVar2[9] = *(undefined4 *)(local_18[0][1] + 0xc);
          puVar2[10] = *(undefined4 *)(local_18[0][1] + 0x10);
          *(undefined *)(puVar2 + 0xb) = *(undefined *)(local_18[0][1] + 0x14);
          local_18[0] = local_18[0] + 2;
          puVar2 = puVar2 + 0xc;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        uVar3 = uVar3 & 1;
        if (uVar3 == 0) goto LAB_800e6f44;
      }
      do {
        *puVar2 = *(undefined4 *)*local_18[0];
        puVar2[1] = *(undefined4 *)(*local_18[0] + 4);
        puVar2[2] = *(undefined4 *)(*local_18[0] + 8);
        puVar2[3] = *(undefined4 *)(*local_18[0] + 0xc);
        puVar2[4] = *(undefined4 *)(*local_18[0] + 0x10);
        *(undefined *)(puVar2 + 5) = *(undefined *)(*local_18[0] + 0x14);
        local_18[0] = local_18[0] + 1;
        puVar2 = puVar2 + 6;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
  }
LAB_800e6f44:
  *param_4 = DAT_803de0f8;
  return &DAT_803a3898;
}

