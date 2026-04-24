// Function: FUN_800e9e64
// Entry: 800e9e64
// Size: 184 bytes

void FUN_800e9e64(void)

{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  DAT_803de10c = 0xff;
  DAT_803de104 = 0xffffffff;
  FUN_80043604(0,0,1);
  uVar3 = 0x884;
  FUN_800033a8(-0x7fc5ba0c,0,0x884);
  FUN_800207d0();
  FUN_80009a94(7);
  FUN_80014a54();
  FUN_8011f678();
  uVar1 = (uint)DAT_803a3f28;
  FUN_80020834((double)(float)(&DAT_803a458c)[uVar1 * 4],(double)(float)(&DAT_803a4590)[uVar1 * 4],
               (double)(float)(&DAT_803a4594)[uVar1 * 4],in_f4,in_f5,in_f6,in_f7,in_f8,
               (int)(char)(&DAT_803a4599)[uVar1 * 0x10],extraout_r4,uVar3,in_r6,in_r7,in_r8,in_r9,
               in_r10);
  iVar2 = FUN_8001496c();
  if (iVar2 != 4) {
    FUN_80014974(1);
  }
  FUN_800d7d90(0x1e,1);
  DAT_803de100 = 2;
  return;
}

