// Function: FUN_80137b80
// Entry: 80137b80
// Size: 424 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80137b80(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  ulonglong uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  char *pcVar7;
  int iVar8;
  uint uVar9;
  byte in_cr1;
  undefined8 extraout_f1;
  ulonglong uVar10;
  undefined8 local_198;
  undefined4 local_190;
  undefined4 local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  undefined8 local_160;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  undefined8 local_140;
  undefined4 local_138;
  undefined *local_134;
  undefined4 local_130;
  byte local_12c [300];
  
  uVar10 = FUN_802860d4();
  if ((bool)(in_cr1 >> 1 & 1)) {
    local_178 = extraout_f1;
    local_170 = param_2;
    local_168 = param_3;
    local_160 = param_4;
    local_158 = param_5;
    local_150 = param_6;
    local_148 = param_7;
    local_140 = param_8;
  }
  local_190 = param_11;
  local_18c = param_12;
  local_188 = param_13;
  local_184 = param_14;
  local_180 = param_15;
  local_17c = param_16;
  local_198 = uVar10;
  if (DAT_803dda28 != '\0') {
    local_138 = 0x3000000;
    local_134 = &stack0x00000008;
    local_130 = &local_198;
    FUN_8028f768(local_12c,param_11,&local_138);
    uVar3 = DAT_803dda30;
    pbVar6 = (byte *)((int)&local_130 + 3);
    pcVar7 = (char *)((int)&local_130 + 3);
    uVar2 = uVar10;
    while( true ) {
      uVar9 = (uint)(uVar2 >> 0x20);
      iVar8 = (int)uVar2;
      pbVar6 = pbVar6 + 1;
      pcVar7 = pcVar7 + 1;
      DAT_803dda30 = uVar3;
      if (*pcVar7 == '\0') break;
      bVar1 = *pbVar6;
      if (bVar1 == 10) {
        uVar2 = uVar10 & 0xffffffff00000000 | (ulonglong)(iVar8 + 0xc);
      }
      else if (bVar1 < 10) {
        if (bVar1 < 9) {
LAB_80137c78:
          if ((0x60 < bVar1) && (bVar1 < 0x7b)) {
            *pbVar6 = *pbVar6 - 0x20;
          }
          uVar4 = (uint)*pbVar6;
          if ((0x20 < uVar4) && (uVar4 < 0x5b)) {
            DAT_803dda30 = DAT_803dccec;
            iVar5 = (uVar4 - 0x21) * 5 + -0x7fce2fa0;
            FUN_80137a00(uVar9,iVar8,iVar5,0xffffffff);
            DAT_803dda30 = DAT_803dcce8;
            FUN_80137a00(uVar9,iVar8,iVar5,0xffffffff);
            uVar2 = uVar2 & 0xffffffff | (ulonglong)(uVar9 + 0xf) << 0x20;
          }
        }
        else {
          uVar2 = uVar2 & 0xffffffff | (ulonglong)(uVar9 + (0x40 - (uVar9 & 0x3f))) << 0x20;
        }
      }
      else {
        if (bVar1 != 0x20) goto LAB_80137c78;
        uVar2 = uVar2 & 0xffffffff | (ulonglong)(uVar9 + 8) << 0x20;
      }
    }
  }
  FUN_80286120();
  return;
}

