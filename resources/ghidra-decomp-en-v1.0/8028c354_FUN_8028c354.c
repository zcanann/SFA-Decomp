// Function: FUN_8028c354
// Entry: 8028c354
// Size: 368 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint FUN_8028c354(uint param_1,uint param_2,undefined4 param_3,int *param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  
  uVar4 = DAT_80332308;
  uVar3 = _DAT_80332304;
  uVar2 = DAT_80332300;
  uVar1 = DAT_803322fc;
  if (param_2 < 0x61) {
    DAT_80332308 = DAT_80332308 & 0xff00ffff;
    *param_4 = 0;
    if (param_1 <= param_2) {
      iVar6 = param_2 - param_1;
      iVar5 = iVar6 + 1;
      *param_4 = *param_4 + iVar5 * 4;
      puVar7 = &DAT_803d8548 + param_1;
      if (param_5 == 0) {
        if ((puVar7 < (undefined4 *)0x803d858d) && ((undefined4 *)0x803d8587 < puVar7 + iVar6)) {
          DAT_803322f0 = 1;
        }
        if ((puVar7 < (undefined4 *)0x803d8619) && ((undefined4 *)0x803d8617 < puVar7 + iVar6)) {
          DAT_803322f1 = 1;
        }
        param_1 = FUN_80286ed8(param_3,puVar7,iVar5);
      }
      else {
        param_1 = FUN_80287348(param_3,puVar7,iVar5);
      }
    }
    if (DAT_80332308._1_1_ != '\0') {
      param_1 = 0x702;
      *param_4 = 0;
    }
  }
  else {
    param_1 = 0x701;
  }
  DAT_803322fc = uVar1;
  DAT_80332300 = uVar2;
  _DAT_80332304 = uVar3;
  DAT_80332308 = uVar4;
  return param_1;
}

