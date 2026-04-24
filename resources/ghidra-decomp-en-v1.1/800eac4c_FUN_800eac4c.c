// Function: FUN_800eac4c
// Entry: 800eac4c
// Size: 960 bytes

int FUN_800eac4c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                uint param_9)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 in_r7;
  int iVar9;
  undefined4 in_r8;
  int iVar10;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar11;
  undefined uVar12;
  double dVar13;
  undefined4 *local_18 [3];
  
  puVar11 = *(undefined2 **)(param_9 + 0xb8);
  *(undefined *)(puVar11 + 4) = 0;
  *(byte *)((int)puVar11 + 7) = *(byte *)((int)puVar11 + 7) & 0xfe;
  iVar5 = FUN_8002bac4();
  if (*(char *)((int)puVar11 + 5) == '\0') {
    uVar12 = 0;
    if ((((*(byte *)(*(int *)(param_9 + 0x78) + (uint)*(byte *)(param_9 + 0xe4) * 5 + 4) & 0xf) == 6
         ) && (uVar6 = FUN_80014b50(0), (uVar6 & 0x100) == 0)) &&
       (((*(byte *)(param_9 + 0xaf) & 1) != 0 && (*(int *)(param_9 + 0xf8) == 0)))) {
      *puVar11 = 0;
      FUN_80014b68(0,0x100);
      uVar12 = 1;
    }
    *(undefined *)((int)puVar11 + 5) = uVar12;
    if (*(char *)((int)puVar11 + 5) != '\0') {
      *(byte *)((int)puVar11 + 7) = *(byte *)((int)puVar11 + 7) | 1;
      *(undefined *)(puVar11 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      FUN_80035f9c(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      if ((*(byte *)((int)puVar11 + 7) & 2) == 0) {
        *(float *)(param_9 + 0x28) = -(FLOAT_803e135c * FLOAT_803dc074 - *(float *)(param_9 + 0x28))
        ;
        *(float *)(param_9 + 0x10) =
             *(float *)(param_9 + 0x28) * FLOAT_803dc074 + *(float *)(param_9 + 0x10);
      }
      iVar7 = FUN_80065fcc((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      iVar9 = 0;
      iVar10 = 0;
      puVar8 = local_18[0];
      iVar5 = iVar7;
      if (0 < iVar7) {
        do {
          if (*(char *)((float *)*puVar8 + 5) != '\x0e') {
            fVar2 = *(float *)*puVar8;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               (fVar2 - FLOAT_803e1360 < *(float *)(param_9 + 0x10))) {
              iVar9 = ((undefined4 *)local_18[0][iVar10])[4];
              *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)local_18[0][iVar10];
              *(float *)(param_9 + 0x28) = FLOAT_803e1364;
              break;
            }
          }
          puVar8 = puVar8 + 1;
          iVar10 = iVar10 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      fVar4 = FLOAT_803e1368;
      fVar2 = FLOAT_803e1364;
      iVar5 = 0;
      if (0 < iVar7) {
        do {
          fVar3 = *(float *)(param_9 + 0x10) - **(float **)((int)local_18[0] + iVar5);
          if (fVar3 < fVar2) {
            fVar3 = -fVar3;
          }
          if ((fVar3 < fVar4) &&
             (cVar1 = *(char *)(*(float **)((int)local_18[0] + iVar5) + 5),
             (int)(uint)*(byte *)(puVar11 + 4) < (int)cVar1)) {
            *(char *)(puVar11 + 4) = cVar1;
          }
          iVar5 = iVar5 + 4;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      if (iVar9 != 0) {
        iVar5 = *(int *)(iVar9 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    dVar13 = (double)FUN_80035f84(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar6 = FUN_80014e9c(0);
    if ((uVar6 & 0x100) != 0) {
      if (((*(byte *)((int)puVar11 + 7) & 4) == 0) && (uVar6 = FUN_80296350(iVar5), uVar6 != 0)) {
        dVar13 = (double)FUN_80014b68(0,0x100);
        *(undefined *)(puVar11 + 3) = 0;
      }
      else {
        dVar13 = (double)FUN_8000bb38(0,0x10a);
      }
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar11 + 5) = 2;
    }
    if (((*(char *)((int)puVar11 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) &&
       (*(short *)(param_9 + 0x46) != 0x112)) {
      iVar7 = *(int *)(param_9 + 0xb8);
      *(undefined *)(iVar7 + 5) = 0;
      *(undefined *)(iVar7 + 6) = 0;
      if ((*(byte *)(iVar7 + 7) & 8) == 0) {
        *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) + FLOAT_803e1358;
        FUN_800e85f4(param_9);
        dVar13 = (double)*(float *)(param_9 + 0x10);
        *(float *)(param_9 + 0x10) = (float)(dVar13 - (double)FLOAT_803e1358);
      }
    }
    if (*(char *)(puVar11 + 3) != '\0') {
      FUN_800379bc(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar11[1],*puVar11),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return (int)*(char *)((int)puVar11 + 5);
}

