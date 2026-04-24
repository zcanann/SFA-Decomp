// Function: FUN_8028c990
// Entry: 8028c990
// Size: 216 bytes

/* WARNING: This function may have set the stack pointer */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
FUN_8028c990(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 in_r0;
  int iVar1;
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
  byte in_cr0;
  byte in_cr1;
  byte in_cr2;
  byte in_cr3;
  byte unaff_cr4;
  byte in_cr5;
  byte in_cr6;
  byte in_cr7;
  undefined4 in_LR;
  undefined4 uVar2;
  
  DAT_803d83a8 = &FLOAT_803e6500;
  DAT_803d83d4 = &FLOAT_803e31e0;
  DAT_803d8428 = (uint)(in_cr0 & 0xf) << 0x1c | (uint)(in_cr1 & 0xf) << 0x18 |
                 (uint)(in_cr2 & 0xf) << 0x14 | (uint)(in_cr3 & 0xf) << 0x10 |
                 (uint)(unaff_cr4 & 0xf) << 0xc | (uint)(in_cr5 & 0xf) << 8 |
                 (uint)(in_cr6 & 0xf) << 4 | (uint)(in_cr7 & 0xf);
  DAT_803d83a0 = in_r0;
  DAT_803d83a4 = (undefined *)register0x00000004;
  DAT_803d83ac = param_1;
  DAT_803d83b0 = param_2;
  DAT_803d83b4 = param_3;
  DAT_803d83b8 = param_4;
  DAT_803d83bc = param_5;
  DAT_803d83c0 = param_6;
  DAT_803d83c4 = param_7;
  DAT_803d83c8 = param_8;
  DAT_803d83cc = in_r11;
  DAT_803d83d0 = in_r12;
  DAT_803d83d8 = unaff_r14;
  DAT_803d83dc = unaff_r15;
  DAT_803d83e0 = unaff_r16;
  DAT_803d83e4 = unaff_r17;
  DAT_803d83e8 = unaff_r18;
  DAT_803d83ec = unaff_r19;
  DAT_803d83f0 = unaff_r20;
  DAT_803d83f4 = unaff_r21;
  DAT_803d83f8 = unaff_r22;
  DAT_803d83fc = unaff_r23;
  DAT_803d8400 = unaff_r24;
  DAT_803d8404 = unaff_r25;
  DAT_803d8408 = unaff_r26;
  DAT_803d840c = unaff_r27;
  DAT_803d8410 = unaff_r28;
  DAT_803d8414 = unaff_r29;
  DAT_803d8418 = unaff_r30;
  DAT_803d841c = unaff_r31;
  DAT_803d8420 = in_LR;
  DAT_803d8424 = in_LR;
  FUN_8028cad0((in_MSR | 0x8000) ^ 0x8000);
  uVar2 = 0x8028ca08;
  iVar1 = FUN_8028d200(DAT_803d83b4,DAT_803d83b0,DAT_803d83b4,DAT_803d83b8,DAT_803d83bc,DAT_803d83c0
                       ,DAT_803d83c4,DAT_803d83c8);
  if (iVar1 == 1) {
    return uRam0000000d;
  }
  _DAT_803fa468 = 0x803fa478;
  _DAT_803fa47c = uVar2;
  DAT_803d8880 = FUN_80286bc8();
  if (DAT_803d8880 == 0) {
    FUN_80286b7c();
    FUN_8028685c();
  }
  DAT_803d8880 = FUN_80286ba4();
  return CONCAT44(DAT_803d8880,0x803e0000);
}

