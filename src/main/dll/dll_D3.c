#include "ghidra_import.h"
#include "main/dll/dll_D3.h"

extern undefined4 FUN_80021754();
extern void* FUN_80037048();
extern int FUN_80296878();

extern f32 FLOAT_803e3088;

/*
 * --INFO--
 *
 * Function: FUN_8013f20c
 * EN v1.0 Address: 0x8013F20C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8013f20c(int param_1,int param_2)
{
  int iVar1;
  int *piVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  int local_38 [3];
  
  iVar1 = *(int *)(param_2 + 0x24);
  if (*(short *)(iVar1 + 0x46) != 0x6a3) {
    iVar1 = FUN_80296878(*(int *)(param_2 + 4));
    if ((iVar1 != 0) && (piVar2 = FUN_80037048(3,local_38), 0 < local_38[0])) {
      do {
        if (*piVar2 == iVar1) {
          dVar3 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
          dVar4 = (double)FUN_80021754((float *)(param_1 + 0x18),
                                       (float *)(*(int *)(param_2 + 4) + 0x18));
          dVar5 = (double)FUN_80021754((float *)(iVar1 + 0x18),
                                       (float *)(*(int *)(param_2 + 4) + 0x18));
          if ((float)(dVar3 + dVar4) < (float)((double)FLOAT_803e3088 * dVar5)) {
            return iVar1;
          }
          break;
        }
        piVar2 = piVar2 + 1;
        local_38[0] = local_38[0] + -1;
      } while (local_38[0] != 0);
    }
    iVar1 = 0;
  }
  return iVar1;
}
