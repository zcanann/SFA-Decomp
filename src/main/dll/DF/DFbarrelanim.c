#include "ghidra_import.h"
#include "main/dll/DF/DFbarrelanim.h"

extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern double FUN_80247f54();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern f64 DOUBLE_803e5a88;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94;

/*
 * --INFO--
 *
 * Function: FUN_801c1238
 * EN v1.0 Address: 0x801C1238
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x801C1414
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c1238(void)
{
  undefined4 *puVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  float afStack_58 [3];
  float afStack_4c [3];
  float local_40;
  float local_3c;
  float local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar1 = (undefined4 *)FUN_80286840();
  pfVar5 = (float *)*puVar1;
  dVar8 = (double)lbl_803E5A94;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(puVar1 + 2); iVar3 = iVar3 + 1) {
    local_38 = (float)dVar8;
    local_3c = (float)dVar8;
    local_40 = (float)dVar8;
    if (*(char *)(pfVar5 + 0xc) == '\0') {
      pfVar6 = pfVar5;
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar5 + 9); iVar4 = iVar4 + 1) {
        fVar2 = pfVar6[10];
        if (pfVar5 == *(float **)((int)fVar2 + 4)) {
          FUN_80247e94(&local_40,(float *)((int)fVar2 + 0x18),&local_40);
        }
        else {
          FUN_80247eb8(&local_40,(float *)((int)fVar2 + 0x18),&local_40);
        }
        pfVar6 = pfVar6 + 1;
      }
      dVar7 = FUN_80247f54(&local_40);
      if ((double)(float)puVar1[0xb] < dVar7) {
        FUN_80247edc((double)(float)((double)(float)puVar1[0xb] / dVar7),&local_40,&local_40);
      }
      FUN_80247edc((double)(float)puVar1[0x10],&local_40,&local_40);
      FUN_80247e94(&local_40,pfVar5 + 6,&local_40);
      FUN_80247e94(pfVar5 + 3,&local_40,pfVar5 + 3);
      FUN_80247edc((double)(float)puVar1[0xe],pfVar5 + 3,afStack_4c);
      FUN_80247eb8(pfVar5 + 3,afStack_4c,pfVar5 + 3);
      pfVar5[4] = (float)puVar1[0xc] * (float)puVar1[0xf] + pfVar5[4];
      FUN_80247edc((double)(float)puVar1[0xc],pfVar5 + 3,afStack_58);
      FUN_80247e94(pfVar5,afStack_58,pfVar5);
    }
    pfVar5 = pfVar5 + 0xd;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c1450
 * EN v1.0 Address: 0x801C1450
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C158C
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c1450(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c1454
 * EN v1.0 Address: 0x801C1454
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x801C176C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c1454(int param_1,int param_2,int param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0;
  for (iVar1 = param_2; iVar2 = param_3, *(int *)(iVar1 + 0x28) != 0; iVar1 = iVar1 + 4) {
    iVar3 = iVar3 + 1;
  }
  for (; *(int *)(iVar2 + 0x28) != 0; iVar2 = iVar2 + 4) {
    iVar4 = iVar4 + 1;
  }
  if (iVar3 <= (int)(uint)*(byte *)(param_2 + 0x24)) {
    if (iVar4 <= (int)(uint)*(byte *)(param_3 + 0x24)) {
      *(int *)(param_2 + iVar3 * 4 + 0x28) = param_1;
      *(int *)(param_3 + iVar4 * 4 + 0x28) = param_1;
      *(int *)(param_1 + 4) = param_2;
      *(int *)(param_1 + 8) = param_3;
      return;
    }
    return;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dfropenode_func12
 * EN v1.0 Address: 0x801C1618
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_func12(int obj, float value)
{
  *(float *)(*(int *)(obj + 0xb8) + 0x14) = value;
}

/*
 * --INFO--
 *
 * Function: dfropenode_func13
 * EN v1.0 Address: 0x801C1688
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_func13(int obj)
{
  int value = 0;
  int extra = *(int *)(obj + 0xb8);

  *(int *)extra = value;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_func0F
 * EN v1.0 Address: 0x801C167C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfropenode_func0F(int obj)
{
  return *(short *)(*(int *)(obj + 0xb8) + 0x18);
}
