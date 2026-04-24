// Function: FUN_8028b354
// Entry: 8028b354
// Size: 472 bytes

/* WARNING: This function may have set the stack pointer */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 *
FUN_8028b354(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 in_r0;
  undefined4 *puVar1;
  undefined4 uVar2;
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
  uint uVar3;
  undefined4 in_XER;
  undefined4 in_LR;
  undefined4 in_CTR;
  undefined4 in_DSISR;
  undefined4 in_DAR;
  undefined4 in_SRR1;
  undefined4 uStack24;
  int iStack20;
  undefined auStack16 [16];
  
  DAT_803d8304 = &FLOAT_803e6500;
  DAT_803d8308 = &DAT_803d82fc;
  DAT_803d8330 = &FLOAT_803e31e0;
  uVar3 = in_MSR & 0x9000;
  DAT_803d82fc = in_r0;
  DAT_803d8300 = (undefined *)register0x00000004;
  DAT_803d830c = param_2;
  DAT_803d8310 = param_3;
  DAT_803d8314 = param_4;
  DAT_803d8318 = param_5;
  DAT_803d831c = param_6;
  DAT_803d8320 = param_7;
  DAT_803d8324 = param_8;
  DAT_803d8328 = in_r11;
  DAT_803d832c = in_r12;
  DAT_803d8334 = unaff_r14;
  DAT_803d8338 = unaff_r15;
  DAT_803d833c = unaff_r16;
  DAT_803d8340 = unaff_r17;
  DAT_803d8344 = unaff_r18;
  DAT_803d8348 = unaff_r19;
  DAT_803d834c = unaff_r20;
  DAT_803d8350 = unaff_r21;
  DAT_803d8354 = unaff_r22;
  DAT_803d8358 = unaff_r23;
  DAT_803d835c = unaff_r24;
  DAT_803d8360 = unaff_r25;
  DAT_803d8364 = unaff_r26;
  DAT_803d8368 = unaff_r27;
  DAT_803d836c = unaff_r28;
  DAT_803d8370 = unaff_r29;
  DAT_803d8374 = unaff_r30;
  DAT_803d8378 = unaff_r31;
  DAT_803d837c = in_LR;
  DAT_803d8380 = in_CTR;
  DAT_803d8384 = in_XER;
  DAT_803d8388 = in_MSR;
  DAT_803d838c = in_DAR;
  DAT_803d8390 = in_DSISR;
  if (*DAT_803d839c != '\0') {
    _DAT_803d8398 = CONCAT13(1,DAT_803d8398_1);
    sync(0);
    sync(0);
    puVar1 = &DAT_803d82fc;
    if (_DAT_803d8398 == 0) {
      uVar3 = DAT_803d8698 & 0xffff;
      if ((uVar3 == 0xd00) || ((uVar3 < 0xd00 && (uVar3 == 0x700)))) {
        uStack24 = 4;
        FUN_8028c6f4(&iStack20,DAT_803d8420,&uStack24,0,1,param_6,param_7,param_8);
        if (iStack20 == 0xfe00000) {
          uVar2 = 5;
        }
        else {
          uVar2 = 3;
        }
      }
      else {
        uVar2 = 4;
      }
      FUN_80286978(auStack16,uVar2);
      puVar1 = (undefined4 *)FUN_80286990(auStack16);
    }
    else {
      _DAT_803d8398 = 0;
    }
    return puVar1;
  }
  DAT_80332308._0_1_ = 0;
  FUN_8028cc88();
  returnFromInterrupt(uVar3,in_SRR1);
  return DAT_803d83ac;
}

