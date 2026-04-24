#include "ghidra_import.h"
#include "main/dll/DIM/DIMbossspit.h"

extern undefined4 FUN_8002bac4();
extern undefined4 FUN_8003042c();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f32 FLOAT_803de81c;
extern f32 FLOAT_803de820;
extern f32 FLOAT_803e5928;
extern f32 FLOAT_803e592c;

/*
 * --INFO--
 *
 * Function: FUN_801be2ac
 * EN v1.0 Address: 0x801BE19C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801BE2AC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801be2ac(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

/*
 * --INFO--
 *
 * Function: FUN_801be318
 * EN v1.0 Address: 0x801BE200
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801BE318
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801be318(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(undefined *)(param_2 + 0x27a) = 1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801be368
 * EN v1.0 Address: 0x801BE250
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x801BE368
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801be368(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            )
{
  undefined4 uVar1;
  ushort *puVar2;
  undefined *puVar3;
  undefined *puVar4;
  int iVar5;
  undefined4 in_r10;
  undefined auStack_18 [2];
  undefined auStack_16 [2];
  ushort local_14 [6];
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FLOAT_803de81c = FLOAT_803de820;
    uVar1 = FUN_8002bac4();
    puVar2 = local_14;
    puVar3 = auStack_16;
    puVar4 = auStack_18;
    iVar5 = *DAT_803dd738;
    (**(code **)(iVar5 + 0x14))(param_9,uVar1,4);
    if (local_14[0] == 1) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,3,0,puVar2,puVar3,puVar4,iVar5,in_r10);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (local_14[0] == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,0,puVar2,puVar3,puVar4,iVar5,in_r10);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (local_14[0] < 3) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,2,0,puVar2,puVar3,puVar4,iVar5,in_r10);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,4,0,puVar2,puVar3,puVar4,iVar5,in_r10);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(float *)(param_10 + 0x2a0) = FLOAT_803e592c;
  }
  return 0;
}
