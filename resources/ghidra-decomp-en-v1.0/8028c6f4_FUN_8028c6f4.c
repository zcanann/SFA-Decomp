// Function: FUN_8028c6f4
// Entry: 8028c6f4
// Size: 332 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_8028c6f4(undefined4 param_1,int param_2,undefined4 *param_3,undefined4 param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  
  uVar4 = DAT_80332308;
  uVar3 = _DAT_80332304;
  uVar2 = DAT_80332300;
  uVar1 = DAT_803322fc;
  DAT_80332308 = DAT_80332308 & 0xff00ffff;
  iVar6 = FUN_8028ca70(param_2);
  uVar5 = countLeadingZeros(param_5);
  iVar7 = FUN_8028c840(iVar6,*param_3,uVar5 >> 5);
  if (iVar7 == 0) {
    uVar5 = FUN_8028b0d8();
    if (param_5 == 0) {
      FUN_8028b0e8(iVar6,param_1,*param_3,uVar5 | DAT_803d8598 & 0x10,uVar5);
      FUN_8028afe4(iVar6,*param_3);
      if (param_2 != iVar6) {
        FUN_8028afe4(param_2,*param_3);
      }
    }
    else {
      FUN_8028b0e8(param_1,iVar6,*param_3,uVar5);
    }
  }
  else {
    *param_3 = 0;
  }
  if (DAT_80332308._1_1_ != '\0') {
    iVar7 = 0x702;
    *param_3 = 0;
  }
  DAT_803322fc = uVar1;
  DAT_80332300 = uVar2;
  _DAT_80332304 = uVar3;
  DAT_80332308 = uVar4;
  return iVar7;
}

