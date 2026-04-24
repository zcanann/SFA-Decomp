// Function: FUN_8028d0f0
// Entry: 8028d0f0
// Size: 148 bytes

/* WARNING: This function may have set the stack pointer */

undefined8
FUN_8028d0f0(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 in_r0;
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
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
  byte in_cr0;
  byte in_cr1;
  byte in_cr2;
  byte in_cr3;
  byte unaff_cr4;
  byte in_cr5;
  byte in_cr6;
  byte in_cr7;
  undefined4 in_LR;
  undefined8 uVar8;
  
  DAT_803d9008 = &FLOAT_803e7180;
  DAT_803d9034 = &FLOAT_803e3e40;
  DAT_803d9088 = (uint)(in_cr0 & 0xf) << 0x1c | (uint)(in_cr1 & 0xf) << 0x18 |
                 (uint)(in_cr2 & 0xf) << 0x14 | (uint)(in_cr3 & 0xf) << 0x10 |
                 (uint)(unaff_cr4 & 0xf) << 0xc | (uint)(in_cr5 & 0xf) << 8 |
                 (uint)(in_cr6 & 0xf) << 4 | (uint)(in_cr7 & 0xf);
  DAT_803d9000 = in_r0;
  DAT_803d9004 = (undefined *)register0x00000004;
  DAT_803d900c = param_1;
  DAT_803d9010 = param_2;
  DAT_803d9014 = param_3;
  DAT_803d9018 = param_4;
  DAT_803d901c = param_5;
  DAT_803d9020 = param_6;
  DAT_803d9024 = param_7;
  DAT_803d9028 = param_8;
  DAT_803d902c = in_r11;
  DAT_803d9030 = in_r12;
  DAT_803d9038 = unaff_r14;
  DAT_803d903c = unaff_r15;
  DAT_803d9040 = unaff_r16;
  DAT_803d9044 = unaff_r17;
  DAT_803d9048 = unaff_r18;
  DAT_803d904c = unaff_r19;
  DAT_803d9050 = unaff_r20;
  DAT_803d9054 = unaff_r21;
  DAT_803d9058 = unaff_r22;
  DAT_803d905c = unaff_r23;
  DAT_803d9060 = unaff_r24;
  DAT_803d9064 = unaff_r25;
  DAT_803d9068 = unaff_r26;
  DAT_803d906c = unaff_r27;
  DAT_803d9070 = unaff_r28;
  DAT_803d9074 = unaff_r29;
  DAT_803d9078 = unaff_r30;
  DAT_803d907c = unaff_r31;
  DAT_803d9080 = in_LR;
  DAT_803d9084 = in_LR;
  FUN_8028d230();
  iVar2 = DAT_803d9014;
  uVar3 = DAT_803d9018;
  uVar4 = DAT_803d901c;
  uVar5 = DAT_803d9020;
  uVar6 = DAT_803d9024;
  uVar7 = DAT_803d9028;
  uVar8 = FUN_8028d960(DAT_803d9014);
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  if (iVar1 == 1) {
    return uRam0000000d;
  }
  uVar8 = FUN_8028d5a8(iVar1,(int)uVar8,iVar2,uVar3,uVar4,uVar5,uVar6,uVar7);
  return uVar8;
}

