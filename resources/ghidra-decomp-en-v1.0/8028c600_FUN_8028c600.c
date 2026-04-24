// Function: FUN_8028c600
// Entry: 8028c600
// Size: 244 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_8028c600(int param_1,uint param_2,undefined4 param_3,int *param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  
  uVar4 = DAT_80332308;
  uVar3 = _DAT_80332304;
  uVar2 = DAT_80332300;
  uVar1 = DAT_803322fc;
  if (param_2 < 0x25) {
    iVar6 = (param_2 - param_1) + 1;
    DAT_80332308 = DAT_80332308 & 0xff00ffff;
    *param_4 = iVar6 * 4;
    if (param_5 == 0) {
      uVar5 = FUN_80286ed8(param_3,&DAT_803d83a0 + param_1,iVar6);
    }
    else {
      uVar5 = FUN_80287348(param_3,&DAT_803d83a0 + param_1,iVar6);
    }
    if (DAT_80332308._1_1_ != '\0') {
      uVar5 = 0x702;
      *param_4 = 0;
    }
  }
  else {
    uVar5 = 0x701;
  }
  DAT_803322fc = uVar1;
  DAT_80332300 = uVar2;
  _DAT_80332304 = uVar3;
  DAT_80332308 = uVar4;
  return uVar5;
}

