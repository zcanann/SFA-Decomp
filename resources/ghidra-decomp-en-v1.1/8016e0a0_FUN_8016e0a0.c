// Function: FUN_8016e0a0
// Entry: 8016e0a0
// Size: 312 bytes

void FUN_8016e0a0(void)

{
  undefined *puVar1;
  double dVar2;
  float afStack_f8 [12];
  float afStack_c8 [12];
  float afStack_98 [12];
  float afStack_68 [12];
  float afStack_38 [3];
  float local_2c;
  float local_1c;
  float local_c;
  longlong local_8;
  
  if (DAT_803ad338 != '\0') {
    local_8 = (longlong)(int)DAT_803ad330;
    FUN_800737e8((char)(int)DAT_803ad330);
    puVar1 = FUN_8000f56c();
    FUN_80003494((uint)afStack_f8,(uint)puVar1,0x30);
    FUN_8024782c((double)FLOAT_803e3f98,afStack_98,0x78);
    dVar2 = (double)DAT_803ad324;
    FUN_80247a7c(dVar2,(double)(float)(dVar2 * (double)DAT_803ad32c),dVar2,afStack_68);
    FUN_80247618(afStack_68,afStack_98,afStack_68);
    FUN_80247a48((double)(DAT_803ad318 - FLOAT_803dda58),(double)DAT_803ad31c,
                 (double)(DAT_803ad320 - FLOAT_803dda5c),afStack_c8);
    FUN_80247618(afStack_f8,afStack_c8,afStack_f8);
    FUN_80247618(afStack_f8,afStack_68,afStack_38);
    FUN_8025d80c(afStack_38,0);
    FUN_80247618(afStack_f8,afStack_98,afStack_38);
    local_2c = FLOAT_803e3f4c;
    local_1c = FLOAT_803e3f4c;
    local_c = FLOAT_803e3f4c;
    FUN_8025d8c4(afStack_38,0x1e,0);
    FUN_8025d180((double)DAT_803ad328,10,0x14);
  }
  return;
}

