#include "ghidra_import.h"
#include "main/dll/SP/SPshop.h"

extern undefined4 FUN_8000a538();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d8;

/*
 * --INFO--
 *
 * Function: FUN_801d84c4
 * EN v1.0 Address: 0x801D84C4
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d84c4(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)
{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286834();
  puVar3 = (uint *)((ulonglong)uVar7 >> 0x20);
  uVar5 = (uint)uVar7;
  uVar4 = (uint)param_3;
  uVar1 = -uVar4 - 1 | uVar4 + 1;
  uVar6 = (uint)param_4;
  uVar2 = -uVar6 - 1 | uVar6 + 1;
  if ((*puVar3 & uVar5) == 0) {
    if ((((int)uVar2 < 0) && (uVar4 = FUN_80020078(uVar6), uVar4 != 0)) ||
       (uVar4 = FUN_80020078((int)param_5), uVar4 != 0)) {
      if ((int)uVar1 < 0) {
        FUN_800201ac((int)param_3,0);
      }
      if ((int)uVar2 < 0) {
        FUN_800201ac((int)param_4,0);
      }
      FUN_800201ac((int)param_5,1);
      if (param_6 != (int *)0xffffffff) {
        FUN_8000a538(param_6,1);
      }
      *puVar3 = *puVar3 | uVar5;
    }
  }
  else if ((((int)uVar1 < 0) && (uVar4 = FUN_80020078(uVar4), uVar4 != 0)) ||
          (uVar4 = FUN_80020078((int)param_5), uVar4 == 0)) {
    if ((int)uVar1 < 0) {
      FUN_800201ac((int)param_3,0);
    }
    if ((int)uVar2 < 0) {
      FUN_800201ac((int)param_4,0);
    }
    FUN_800201ac((int)param_5,0);
    if (param_6 != (int *)0xffffffff) {
      FUN_8000a538(param_6,0);
    }
    *puVar3 = *puVar3 & ~uVar5;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d8650
 * EN v1.0 Address: 0x801D8650
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8650(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)
{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286838();
  uVar2 = (uint)param_5;
  uVar1 = FUN_80020078(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_800201ac(uVar2,uVar1 >> 5);
  FUN_801d84c4((int)((ulonglong)uVar3 >> 0x20),(int)uVar3,param_3,param_4,param_5,param_6);
  uVar1 = FUN_80020078(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_800201ac(uVar2,uVar1 >> 5);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d86e4
 * EN v1.0 Address: 0x801D86E4
 * EN v1.0 Size: 532b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d86e4(uint *param_1)
{
}
