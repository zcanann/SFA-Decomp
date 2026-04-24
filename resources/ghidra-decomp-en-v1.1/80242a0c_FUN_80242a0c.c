// Function: FUN_80242a0c
// Entry: 80242a0c
// Size: 128 bytes

undefined4 FUN_80242a0c(int param_1)

{
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
  undefined4 in_MSR;
  byte in_cr0;
  byte in_cr1;
  byte in_cr2;
  byte in_cr3;
  byte unaff_cr4;
  byte in_cr5;
  byte in_cr6;
  byte in_cr7;
  undefined4 in_XER;
  undefined4 in_LR;
  undefined4 in_CTR;
  undefined4 unaff_GQR1;
  undefined4 unaff_GQR7;
  
  *(float **)(param_1 + 0x34) = &FLOAT_803e3e40;
  *(undefined4 *)(param_1 + 0x38) = unaff_r14;
  *(undefined4 *)(param_1 + 0x3c) = unaff_r15;
  *(undefined4 *)(param_1 + 0x40) = unaff_r16;
  *(undefined4 *)(param_1 + 0x44) = unaff_r17;
  *(undefined4 *)(param_1 + 0x48) = unaff_r18;
  *(undefined4 *)(param_1 + 0x4c) = unaff_r19;
  *(undefined4 *)(param_1 + 0x50) = unaff_r20;
  *(undefined4 *)(param_1 + 0x54) = unaff_r21;
  *(undefined4 *)(param_1 + 0x58) = unaff_r22;
  *(undefined4 *)(param_1 + 0x5c) = unaff_r23;
  *(undefined4 *)(param_1 + 0x60) = unaff_r24;
  *(undefined4 *)(param_1 + 100) = unaff_r25;
  *(undefined4 *)(param_1 + 0x68) = unaff_r26;
  *(undefined4 *)(param_1 + 0x6c) = unaff_r27;
  *(undefined4 *)(param_1 + 0x70) = unaff_r28;
  *(undefined4 *)(param_1 + 0x74) = unaff_r29;
  *(undefined4 *)(param_1 + 0x78) = unaff_r30;
  *(undefined4 *)(param_1 + 0x7c) = unaff_r31;
  *(undefined4 *)(param_1 + 0x1a8) = unaff_GQR1;
  *(undefined4 *)(param_1 + 0x1ac) = 0x40004;
  *(undefined4 *)(param_1 + 0x1b0) = 0x50005;
  *(undefined4 *)(param_1 + 0x1b4) = 0x60006;
  *(undefined4 *)(param_1 + 0x1b8) = 0x70007;
  *(undefined4 *)(param_1 + 0x1bc) = 0x3d043d04;
  *(undefined4 *)(param_1 + 0x1c0) = unaff_GQR7;
  *(uint *)(param_1 + 0x80) =
       (uint)(in_cr0 & 0xf) << 0x1c | (uint)(in_cr1 & 0xf) << 0x18 | (uint)(in_cr2 & 0xf) << 0x14 |
       (uint)(in_cr3 & 0xf) << 0x10 | (uint)(unaff_cr4 & 0xf) << 0xc | (uint)(in_cr5 & 0xf) << 8 |
       (uint)(in_cr6 & 0xf) << 4 | (uint)(in_cr7 & 0xf);
  *(undefined4 *)(param_1 + 0x84) = in_LR;
  *(undefined4 *)(param_1 + 0x198) = in_LR;
  *(undefined4 *)(param_1 + 0x19c) = in_MSR;
  *(undefined4 *)(param_1 + 0x88) = in_CTR;
  *(undefined4 *)(param_1 + 0x8c) = in_XER;
  *(BADSPACEBASE **)(param_1 + 4) = register0x00000004;
  *(float **)(param_1 + 8) = &FLOAT_803e7180;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return 0;
}

