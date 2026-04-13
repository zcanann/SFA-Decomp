// Function: FUN_8026de48
// Entry: 8026de48
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8026df68) */

void FUN_8026de48(uint param_1,uint param_2,uint param_3,byte param_4)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined uVar7;
  
  for (puVar6 = DAT_803deeb4; puVar5 = DAT_803deeb0, puVar6 != (undefined4 *)0x0;
      puVar6 = (undefined4 *)*puVar6) {
    if (puVar6[3] == (param_3 & 0x7fffffff)) {
      uVar3 = param_3 & 0x80000000 | (uint)*(byte *)((int)puVar6 + 9);
      goto LAB_8026decc;
    }
  }
  do {
    if (puVar5 == (undefined4 *)0x0) {
      uVar3 = 0xffffffff;
LAB_8026decc:
      if (uVar3 != 0xffffffff) {
        if ((uVar3 & 0x80000000) == 0) {
          FUN_802722b0(param_1,param_2,(uint)*(byte *)(uVar3 * 0x1868 + -0x7fc4dba0),param_4,param_3
                      );
          puVar5 = &DAT_803b15b0 + uVar3 * 0x61a;
          uVar4 = 0;
          puVar6 = puVar5;
          do {
            if (*(char *)(puVar6 + 0xc9) != *(char *)(uVar3 * 0x1868 + -0x7fc4dba0)) {
              FUN_802722b0(param_1,param_2,(uint)*(byte *)(puVar5 + 0xc9),0,0xffffffff);
            }
            uVar4 = uVar4 + 1;
            puVar6 = (undefined4 *)((int)puVar6 + 1);
            puVar5 = (undefined4 *)((int)puVar5 + 1);
          } while (uVar4 < 0x40);
        }
        else {
          bVar1 = param_4 & 0xf;
          uVar3 = uVar3 & 0x7fffffff;
          uVar7 = (undefined)param_1;
          if (bVar1 == 2) {
            iVar2 = uVar3 * 0x1868;
            (&DAT_803b248a)[iVar2] = (&DAT_803b248a)[iVar2] | 8;
            *(undefined *)(iVar2 + -0x7fc4db84) = uVar7;
          }
          else if (bVar1 < 2) {
            if ((param_4 & 0xf) == 0) {
              *(undefined *)(uVar3 * 0x1868 + -0x7fc4db84) = uVar7;
            }
            else {
              *(undefined4 *)(uVar3 * 0x1868 + -0x7fc4db74) = 0;
            }
          }
          else if (bVar1 < 4) {
            iVar2 = uVar3 * 0x1868;
            (&DAT_803b248a)[iVar2] = (&DAT_803b248a)[iVar2] | 0x80;
            *(undefined *)(iVar2 + -0x7fc4db84) = uVar7;
          }
        }
      }
      return;
    }
    if (puVar5[3] == (param_3 & 0x7fffffff)) {
      uVar3 = param_3 & 0x80000000 | (uint)*(byte *)((int)puVar5 + 9);
      goto LAB_8026decc;
    }
    puVar5 = (undefined4 *)*puVar5;
  } while( true );
}

