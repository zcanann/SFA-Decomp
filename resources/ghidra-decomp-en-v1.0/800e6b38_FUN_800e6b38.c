// Function: FUN_800e6b38
// Entry: 800e6b38
// Size: 428 bytes

undefined4 *
FUN_800e6b38(undefined8 param_1,undefined8 param_2,int param_3,uint *param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  int *local_18 [5];
  
  if (param_3 != DAT_803dd484) {
    if (param_5 == 0) {
      uVar1 = 0xfffffffe;
    }
    else {
      uVar1 = 1;
    }
    DAT_803dd484 = param_3;
    DAT_803dd480 = FUN_80065e50(param_1,(double)*(float *)(param_3 + 0x1c),param_2,param_3,local_18,
                                uVar1,0);
    if (0x23 < (int)DAT_803dd480) {
      DAT_803dd480 = 0x23;
    }
    uVar3 = DAT_803dd480;
    puVar2 = &DAT_803a2c38;
    if (0 < (int)DAT_803dd480) {
      uVar4 = DAT_803dd480 >> 1;
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
        if (uVar3 == 0) goto LAB_800e6cc0;
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
LAB_800e6cc0:
  *param_4 = DAT_803dd480;
  return &DAT_803a2c38;
}

