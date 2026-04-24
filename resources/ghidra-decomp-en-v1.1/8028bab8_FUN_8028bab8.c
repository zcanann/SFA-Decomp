// Function: FUN_8028bab8
// Entry: 8028bab8
// Size: 280 bytes

/* WARNING: This function may have set the stack pointer */

undefined4
FUN_8028bab8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 in_r0;
  undefined4 uVar1;
  undefined4 in_r11;
  undefined4 in_r12;
  undefined4 unaff_r14;
  undefined4 unaff_r15;
  undefined4 unaff_r16;
  undefined4 unaff_r17;
  undefined4 unaff_r18;
  undefined4 unaff_r19;
  undefined4 unaff_r20;
  undefined4 unaff_r21;
  undefined4 unaff_r22;
  undefined4 unaff_r23;
  undefined4 unaff_r24;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  uint in_MSR;
  uint uVar2;
  undefined4 in_XER;
  undefined4 in_LR;
  undefined4 in_CTR;
  undefined4 in_DSISR;
  undefined4 in_DAR;
  undefined4 in_SRR1;
  
  DAT_803d8f64 = &FLOAT_803e7180;
  DAT_803d8f68 = &DAT_803d8f5c;
  DAT_803d8f90 = &FLOAT_803e3e40;
  uVar2 = in_MSR & 0x9000;
  DAT_803d8f5c = in_r0;
  DAT_803d8f60 = (undefined *)register0x00000004;
  DAT_803d8f6c = param_2;
  DAT_803d8f70 = param_3;
  DAT_803d8f74 = param_4;
  DAT_803d8f78 = param_5;
  DAT_803d8f7c = param_6;
  DAT_803d8f80 = param_7;
  DAT_803d8f84 = param_8;
  DAT_803d8f88 = in_r11;
  DAT_803d8f8c = in_r12;
  DAT_803d8f94 = unaff_r14;
  DAT_803d8f98 = unaff_r15;
  DAT_803d8f9c = unaff_r16;
  DAT_803d8fa0 = unaff_r17;
  DAT_803d8fa4 = unaff_r18;
  DAT_803d8fa8 = unaff_r19;
  DAT_803d8fac = unaff_r20;
  DAT_803d8fb0 = unaff_r21;
  DAT_803d8fb4 = unaff_r22;
  DAT_803d8fb8 = unaff_r23;
  DAT_803d8fbc = unaff_r24;
  DAT_803d8fc0 = unaff_r25;
  DAT_803d8fc4 = unaff_r26;
  DAT_803d8fc8 = unaff_r27;
  DAT_803d8fcc = unaff_r28;
  DAT_803d8fd0 = unaff_r29;
  DAT_803d8fd4 = unaff_r30;
  DAT_803d8fd8 = unaff_r31;
  DAT_803d8fdc = in_LR;
  DAT_803d8fe0 = in_CTR;
  DAT_803d8fe4 = in_XER;
  DAT_803d8fe8 = in_MSR;
  DAT_803d8fec = in_DAR;
  DAT_803d8ff0 = in_DSISR;
  if (*DAT_803d8ffc != '\0') {
    DAT_803d8ff8._0_1_ = 1;
    sync(0);
    sync(0);
    uVar1 = FUN_8028c494();
    return uVar1;
  }
  DAT_80332f68._0_1_ = 0;
  FUN_8028d3e8();
  returnFromInterrupt(uVar2,in_SRR1);
  return DAT_803d900c;
}

