// Function: FUN_801793b8
// Entry: 801793b8
// Size: 628 bytes

void FUN_801793b8(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  float fVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  short local_38 [2];
  short local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  psVar5 = (short *)FUN_8002b9ec();
  iVar8 = *(int *)(psVar5 + 0x5c);
  if (*(char *)(param_2 + 0x2c8) != '\x01') {
    if (*(char *)(param_2 + 0x2c9) == '\0') {
      *(undefined *)(param_2 + 0x2c9) = 1;
      if (*(char *)(param_2 + 0x2c9) != '\0') {
        *(undefined *)(param_2 + 0x2ca) = 1;
      }
    }
    else {
      FUN_80035f00(param_1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      FUN_8011f3a8(local_38);
      uVar6 = FUN_80014e70(0);
      if (((uVar6 & 0x100) != 0) ||
         ((local_38[0] == 5 && (uVar6 = FUN_80014e70(0), (uVar6 & 0x800) != 0)))) {
        iVar7 = FUN_80295bf0(psVar5);
        if (iVar7 == 0) {
          FUN_8000bb18(0,0x10a);
        }
        else {
          *(undefined *)(param_2 + 0x2ca) = 0;
        }
      }
      if (*(int *)(param_1 + 0xf8) == 1) {
        *(undefined *)(param_2 + 0x2c9) = 2;
      }
      if ((*(char *)(param_2 + 0x2c9) == '\x02') && (*(int *)(param_1 + 0xf8) == 0)) {
        iVar7 = FUN_8029669c(psVar5);
        if (iVar7 == 0) {
          *(undefined *)(param_2 + 0x2c9) = 0;
          *(undefined *)(param_2 + 0x2ca) = 0;
          *(float *)(param_2 + 0x26c) = FLOAT_803e36a4;
          *(undefined *)(param_2 + 0x274) = 5;
        }
        else {
          *(undefined *)(param_2 + 0x2c9) = 0;
          *(undefined *)(param_2 + 0x2c8) = 1;
          fVar4 = FLOAT_803e3688;
          *(float *)(param_1 + 0x28) =
               FLOAT_803e3688 * (FLOAT_803e3690 * *(float *)(iVar8 + 0x298) + FLOAT_803e368c);
          *(float *)(param_1 + 0x2c) =
               fVar4 * (FLOAT_803e3698 * *(float *)(iVar8 + 0x298) + FLOAT_803e3694);
          local_28 = FLOAT_803e369c;
          local_24 = FLOAT_803e369c;
          local_20 = FLOAT_803e369c;
          local_2c = FLOAT_803e36a0;
          local_30 = 0;
          local_32 = 0;
          if (*(short **)(psVar5 + 0x18) == (short *)0x0) {
            local_34 = *psVar5;
          }
          else {
            local_34 = **(short **)(psVar5 + 0x18) + *psVar5;
          }
          FUN_80021ac8(&local_34,param_1 + 0x24);
          uVar1 = *(undefined4 *)(param_1 + 0x2c);
          uVar2 = *(undefined4 *)(param_1 + 0x28);
          uVar3 = *(undefined4 *)(param_1 + 0x24);
          iVar8 = *(int *)(param_1 + 0xb8);
          *(undefined *)(iVar8 + 0x274) = 3;
          *(float *)(iVar8 + 0x26c) = FLOAT_803e369c;
          *(undefined4 *)(param_1 + 0x24) = uVar3;
          *(undefined4 *)(param_1 + 0x28) = uVar2;
          *(undefined4 *)(param_1 + 0x2c) = uVar1;
          FUN_80035f20(param_1);
          FUN_80035ea4(param_1);
          *(undefined *)(iVar8 + 0x25b) = 1;
          *(undefined4 *)(iVar8 + 0x2b0) = *(undefined4 *)(param_1 + 0xc);
          *(undefined4 *)(iVar8 + 0x2b4) = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(iVar8 + 0x2b8) = *(undefined4 *)(param_1 + 0x14);
        }
      }
      if (*(char *)(param_2 + 0x2ca) != '\0') {
        FUN_800378c4(psVar5,0x100010,param_1,0);
      }
    }
  }
  return;
}

