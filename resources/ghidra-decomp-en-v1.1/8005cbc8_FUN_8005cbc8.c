// Function: FUN_8005cbc8
// Entry: 8005cbc8
// Size: 728 bytes

void FUN_8005cbc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 *puVar1;
  short *psVar2;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined8 uVar5;
  
  DAT_803dda68 = 0;
  DAT_803ddb1c = FUN_80023d8c(0x100,5);
  DAT_803ddb14 = FUN_80023d8c(0x80,5);
  DAT_803ddb0c = FUN_80023d8c(0x40,5);
  DAT_803ddaf8 = FUN_80023d8c(0xd48,5);
  DAT_80382f14 = FUN_80023d8c(0x500,5);
  DAT_80382f00 = FUN_80023d8c(0x3c00,5);
  uVar3 = 0;
  DAT_80382eec = FUN_80023d8c(0x500,5);
  DAT_80382f18 = DAT_80382f14 + 0x100;
  DAT_80382f04 = DAT_80382f00 + 0xc00;
  DAT_80382ef0 = DAT_80382eec + 0x100;
  DAT_80382f1c = DAT_80382f14 + 0x200;
  DAT_80382f08 = DAT_80382f00 + 0x1800;
  DAT_80382ef4 = DAT_80382eec + 0x200;
  DAT_80382f20 = DAT_80382f14 + 0x300;
  DAT_80382f0c = DAT_80382f00 + 0x2400;
  DAT_80382ef8 = DAT_80382eec + 0x300;
  DAT_80382f24 = DAT_80382f14 + 0x400;
  DAT_80382f10 = DAT_80382f00 + 0x3000;
  DAT_80382efc = DAT_80382eec + 0x400;
  uVar5 = FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddafc
                       ,0x1e,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  uVar5 = FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddb00,
                       0x29,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  puVar1 = &DAT_803870c8;
  iVar4 = 3;
  do {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
    puVar1[8] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    puVar1[0xb] = 0;
    puVar1[0xc] = 0;
    puVar1[0xd] = 0;
    puVar1[0xe] = 0;
    puVar1[0xf] = 0;
    puVar1[0x10] = 0;
    puVar1[0x11] = 0;
    puVar1[0x12] = 0;
    puVar1[0x13] = 0;
    puVar1[0x14] = 0;
    puVar1[0x15] = 0;
    puVar1[0x16] = 0;
    puVar1[0x17] = 0;
    puVar1[0x18] = 0;
    puVar1[0x19] = 0;
    puVar1[0x1a] = 0;
    puVar1[0x1b] = 0;
    puVar1[0x1c] = 0;
    puVar1[0x1d] = 0;
    puVar1[0x1e] = 0;
    puVar1[0x1f] = 0;
    puVar1[0x20] = 0;
    puVar1[0x21] = 0;
    puVar1[0x22] = 0;
    puVar1[0x23] = 0;
    puVar1[0x24] = 0;
    puVar1[0x25] = 0;
    puVar1[0x26] = 0;
    puVar1[0x27] = 0;
    puVar1 = puVar1 + 0x28;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddb04,0x27,
               uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  DAT_803ddb10 = 0;
  for (psVar2 = DAT_803ddb04; *psVar2 != -1; psVar2 = psVar2 + 1) {
    DAT_803ddb10 = DAT_803ddb10 + 1;
  }
  DAT_803ddb10 = DAT_803ddb10 + -1;
  DAT_803ddb3a = 0xffff;
  DAT_803ddb38 = 0xfffe;
  DAT_803ddaec = FUN_80023d8c(0x500,5);
  FUN_800033a8(DAT_803ddaec,0,0x500);
  DAT_803ddae8 = FUN_80023d8c(0x3a0,5);
  FUN_800033a8(DAT_803ddae8,0,0x3a0);
  FUN_800033a8(-0x7fc78ac8,0,4000);
  DAT_80387538 = 0xffffffff;
  return;
}

