// Function: FUN_8016dbf4
// Entry: 8016dbf4
// Size: 312 bytes

void FUN_8016dbf4(void)

{
  undefined4 uVar1;
  double dVar2;
  undefined auStack248 [48];
  undefined auStack200 [48];
  undefined auStack152 [48];
  undefined auStack104 [48];
  undefined auStack56 [12];
  float local_2c;
  float local_1c;
  float local_c;
  longlong local_8;
  
  if (DAT_803ac6d8 != '\0') {
    local_8 = (longlong)(int)DAT_803ac6d0;
    FUN_8007366c((int)DAT_803ac6d0);
    uVar1 = FUN_8000f54c();
    FUN_80003494(auStack248,uVar1,0x30);
    FUN_802470c8((double)FLOAT_803e3300,auStack152,0x78);
    dVar2 = (double)DAT_803ac6c4;
    FUN_80247318(dVar2,(double)(float)(dVar2 * (double)DAT_803ac6cc),dVar2,auStack104);
    FUN_80246eb4(auStack104,auStack152,auStack104);
    FUN_802472e4((double)(DAT_803ac6b8 - FLOAT_803dcdd8),(double)DAT_803ac6bc,
                 (double)(DAT_803ac6c0 - FLOAT_803dcddc),auStack200);
    FUN_80246eb4(auStack248,auStack200,auStack248);
    FUN_80246eb4(auStack248,auStack104,auStack56);
    FUN_8025d0a8(auStack56,0);
    FUN_80246eb4(auStack248,auStack152,auStack56);
    local_2c = FLOAT_803e32b4;
    local_1c = FLOAT_803e32b4;
    local_c = FLOAT_803e32b4;
    FUN_8025d160(auStack56,0x1e,0);
    FUN_8025ca1c((double)DAT_803ac6c8,10,0x14);
  }
  return;
}

