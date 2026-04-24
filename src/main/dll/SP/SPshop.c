#include "ghidra_import.h"
#include "main/dll/SP/SPshop.h"

extern undefined4 FUN_800067c0();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d8;

/*
 * --INFO--
 *
 * Function: FUN_801d8308
 * EN v1.0 Address: 0x801D8308
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801D84C4
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8308(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
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
    if ((((int)uVar2 < 0) && (uVar4 = FUN_80017690(uVar6), uVar4 != 0)) ||
       (uVar4 = FUN_80017690((int)param_5), uVar4 != 0)) {
      if ((int)uVar1 < 0) {
        FUN_80017698((int)param_3,0);
      }
      if ((int)uVar2 < 0) {
        FUN_80017698((int)param_4,0);
      }
      FUN_80017698((int)param_5,1);
      if (param_6 != (int *)0xffffffff) {
        FUN_800067c0(param_6,1);
      }
      *puVar3 = *puVar3 | uVar5;
    }
  }
  else if ((((int)uVar1 < 0) && (uVar4 = FUN_80017690(uVar4), uVar4 != 0)) ||
          (uVar4 = FUN_80017690((int)param_5), uVar4 == 0)) {
    if ((int)uVar1 < 0) {
      FUN_80017698((int)param_3,0);
    }
    if ((int)uVar2 < 0) {
      FUN_80017698((int)param_4,0);
    }
    FUN_80017698((int)param_5,0);
    if (param_6 != (int *)0xffffffff) {
      FUN_800067c0(param_6,0);
    }
    *puVar3 = *puVar3 & ~uVar5;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d8480
 * EN v1.0 Address: 0x801D8480
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801D8650
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8480(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)
{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286838();
  uVar2 = (uint)param_5;
  uVar1 = FUN_80017690(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_80017698(uVar2,uVar1 >> 5);
  FUN_801d8308((int)((ulonglong)uVar3 >> 0x20),(int)uVar3,param_3,param_4,param_5,param_6);
  uVar1 = FUN_80017690(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_80017698(uVar2,uVar1 >> 5);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d8524
 * EN v1.0 Address: 0x801D8524
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D86E4
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8524(uint *param_1)
{
}
