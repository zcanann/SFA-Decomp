#include "ghidra_import.h"
#include "main/dll/SH/lily.h"

extern undefined4 FUN_80017690();
extern double FUN_80017714();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_8014ccac();
extern int FUN_80286834();
extern undefined4 FUN_80286880();

extern undefined4 DAT_80327ad8;
extern undefined4 DAT_80327adc;
extern undefined4 DAT_80327ae0;
extern undefined4 DAT_80327ae4;
extern undefined4 DAT_80327ae8;
extern undefined4 DAT_80327af8;
extern undefined4 DAT_80327b08;
extern undefined4 DAT_80327b18;
extern undefined4 DAT_80327b28;
extern f32 lbl_803E60AC;

/*
 * --INFO--
 *
 * Function: FUN_801d5174
 * EN v1.0 Address: 0x801D5174
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x801D52C0
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d5174(void)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  char cVar8;
  double dVar9;
  int local_28 [10];
  
  iVar1 = FUN_80286834();
  cVar8 = -1;
  cVar6 = '\0';
  iVar2 = *(int *)(*(int *)(iVar1 + 0x4c) + 0x14);
  if (iVar2 == DAT_80327ad8) {
    cVar8 = '\0';
  }
  else if (iVar2 == DAT_80327ae8) {
    cVar8 = '\x01';
  }
  else if (iVar2 == DAT_80327af8) {
    cVar8 = '\x02';
  }
  else if (iVar2 == DAT_80327b08) {
    cVar8 = '\x03';
  }
  else if (iVar2 == DAT_80327b18) {
    cVar8 = '\x04';
  }
  else if (iVar2 == DAT_80327b28) {
    cVar8 = '\x05';
  }
  piVar3 = ObjGroup_GetObjects(3,local_28);
  iVar2 = (int)cVar8;
  for (iVar7 = 0; iVar7 < local_28[0]; iVar7 = iVar7 + 1) {
    iVar4 = *piVar3;
    if ((*(short *)(iVar4 + 0x46) == 0x4d7) &&
       (((iVar5 = *(int *)(*(int *)(iVar4 + 0x4c) + 0x14), iVar5 == (&DAT_80327adc)[iVar2 * 4] ||
         (iVar5 == (&DAT_80327ae0)[iVar2 * 4])) || (iVar5 == (&DAT_80327ae4)[iVar2 * 4])))) {
      FUN_8014ccac(iVar4,iVar1);
      dVar9 = FUN_80017714((float *)(*piVar3 + 0x18),(float *)(iVar1 + 0x18));
      if (dVar9 < (double)lbl_803E60AC) {
        FUN_80017690((int)*(short *)(*(int *)(*piVar3 + 0x4c) + 0x18));
      }
      cVar6 = cVar6 + '\x01';
      if (cVar6 == '\x03') break;
    }
    piVar3 = piVar3 + 1;
  }
  FUN_80286880();
  return;
}
