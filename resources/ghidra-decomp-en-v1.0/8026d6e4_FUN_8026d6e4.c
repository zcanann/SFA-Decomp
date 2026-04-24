// Function: FUN_8026d6e4
// Entry: 8026d6e4
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8026d804) */

void FUN_8026d6e4(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined uVar6;
  
  for (puVar5 = DAT_803de234; puVar4 = DAT_803de230, puVar5 != (undefined4 *)0x0;
      puVar5 = (undefined4 *)*puVar5) {
    if (puVar5[3] == (param_3 & 0x7fffffff)) {
      uVar2 = param_3 & 0x80000000 | (uint)*(byte *)((int)puVar5 + 9);
      goto LAB_8026d768;
    }
  }
  do {
    if (puVar4 == (undefined4 *)0x0) {
      uVar2 = 0xffffffff;
LAB_8026d768:
      if (uVar2 != 0xffffffff) {
        if ((uVar2 & 0x80000000) == 0) {
          FUN_80271b4c(param_1,param_2,*(undefined *)(uVar2 * 0x1868 + -0x7fc4e800),param_4,param_3)
          ;
          puVar4 = &DAT_803b0950 + uVar2 * 0x61a;
          uVar3 = 0;
          puVar5 = puVar4;
          do {
            if (*(char *)(puVar5 + 0xc9) != *(char *)(uVar2 * 0x1868 + -0x7fc4e800)) {
              FUN_80271b4c(param_1,param_2,*(undefined *)(puVar4 + 0xc9),0,0xffffffff);
            }
            uVar3 = uVar3 + 1;
            puVar5 = (undefined4 *)((int)puVar5 + 1);
            puVar4 = (undefined4 *)((int)puVar4 + 1);
          } while (uVar3 < 0x40);
        }
        else {
          param_4 = param_4 & 0xf;
          uVar2 = uVar2 & 0x7fffffff;
          uVar6 = (undefined)param_1;
          if (param_4 == 2) {
            iVar1 = uVar2 * 0x1868;
            (&DAT_803b182a)[iVar1] = (&DAT_803b182a)[iVar1] | 8;
            *(undefined *)(iVar1 + -0x7fc4e7e4) = uVar6;
          }
          else if (param_4 < 2) {
            if (param_4 == 0) {
              *(undefined *)(uVar2 * 0x1868 + -0x7fc4e7e4) = uVar6;
            }
            else {
              *(undefined4 *)(uVar2 * 0x1868 + -0x7fc4e7d4) = 0;
            }
          }
          else if (param_4 < 4) {
            iVar1 = uVar2 * 0x1868;
            (&DAT_803b182a)[iVar1] = (&DAT_803b182a)[iVar1] | 0x80;
            *(undefined *)(iVar1 + -0x7fc4e7e4) = uVar6;
          }
        }
      }
      return;
    }
    if (puVar4[3] == (param_3 & 0x7fffffff)) {
      uVar2 = param_3 & 0x80000000 | (uint)*(byte *)((int)puVar4 + 9);
      goto LAB_8026d768;
    }
    puVar4 = (undefined4 *)*puVar4;
  } while( true );
}

